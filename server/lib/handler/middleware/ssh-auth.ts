import * as crypto from 'crypto';
import { DynamoDBDocumentClient, QueryCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { logger } from '../logger.js';

export interface AuthResult {
  tenantId: string;
  publicKey: string;
  fingerprint: string;
}

export class AuthError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

interface ParsedAuthHeader {
  signature: string;
  timestamp: string;
  sequence: number;
}

/** Timestamp tolerance: 30 seconds (replay protection is primarily sequence-based). */
const TIMESTAMP_TOLERANCE_MS = 30 * 1000;

/**
 * Parse the new SSH-Signature authorization scheme.
 *
 * Headers:
 *   Authorization: SSH-Signature <base64-signature>
 *   X-ChaosKB-Timestamp: <ISO 8601>
 *   X-ChaosKB-Sequence: <monotonic counter>
 */
export function parseAuthHeaders(headers: Record<string, string>): ParsedAuthHeader {
  const authHeader = headers['authorization'] || headers['Authorization'];
  if (!authHeader) {
    throw new AuthError('Missing Authorization header', 401);
  }

  if (!authHeader.startsWith('SSH-Signature ')) {
    // Support legacy format during migration
    if (authHeader.startsWith('ChaosKB-SSH ')) {
      return parseLegacyAuthHeader(authHeader, headers);
    }
    throw new AuthError('Invalid authorization scheme', 401);
  }

  const signature = authHeader.slice('SSH-Signature '.length);
  const timestamp = headers['x-chaoskb-timestamp'] || headers['X-ChaosKB-Timestamp'];
  const sequenceStr = headers['x-chaoskb-sequence'] || headers['X-ChaosKB-Sequence'];

  if (!signature || !timestamp) {
    throw new AuthError('Missing required headers (X-ChaosKB-Timestamp)', 401);
  }

  const sequence = sequenceStr ? parseInt(sequenceStr, 10) : 0;
  if (isNaN(sequence)) {
    throw new AuthError('Invalid sequence number', 401);
  }

  return { signature, timestamp, sequence };
}

/** Parse legacy ChaosKB-SSH format for backwards compatibility. */
function parseLegacyAuthHeader(
  header: string,
  headers: Record<string, string>,
): ParsedAuthHeader {
  const params = header.slice('ChaosKB-SSH '.length);
  const fields: Record<string, string> = {};

  for (const part of params.split(', ')) {
    const eqIndex = part.indexOf('=');
    if (eqIndex === -1) continue;
    fields[part.slice(0, eqIndex)] = part.slice(eqIndex + 1);
  }

  if (!fields['sig'] || !fields['ts']) {
    throw new AuthError('Missing required authorization fields', 401);
  }

  const sequenceStr = headers['x-chaoskb-sequence'] || headers['X-ChaosKB-Sequence'];

  return {
    signature: fields['sig'],
    timestamp: fields['ts'],
    sequence: sequenceStr ? parseInt(sequenceStr, 10) : 0,
  };
}

/** Compute SSH key fingerprint (SHA-256 of raw public key, base64). */
export function fingerprintFromPublicKey(publicKeyBase64: string): string {
  return crypto.createHash('sha256').update(Buffer.from(publicKeyBase64, 'base64')).digest('base64');
}

export function verifyTimestamp(timestamp: string): void {
  const requestTime = new Date(timestamp).getTime();
  if (isNaN(requestTime)) {
    throw new AuthError('Invalid timestamp format', 401);
  }

  const now = Date.now();
  const diff = Math.abs(now - requestTime);
  if (diff > TIMESTAMP_TOLERANCE_MS) {
    throw new AuthError('Request timestamp expired', 401);
  }
}

export function buildCanonicalString(
  method: string,
  path: string,
  timestamp: string,
  sequence: number,
  body?: string | null,
): string {
  const bodyHash = body
    ? crypto.createHash('sha256').update(body).digest('hex')
    : '';
  return `chaoskb-auth\n${method} ${path}\n${timestamp}\n${sequence}\n${bodyHash}`;
}

/**
 * Check and update the per-device sequence counter for replay protection.
 *
 * Uses a DynamoDB conditional write: only succeeds if the new sequence
 * is strictly greater than the stored highest-seen sequence.
 */
export async function checkSequence(
  ddb: DynamoDBDocumentClient,
  tableName: string,
  tenantId: string,
  fingerprint: string,
  sequence: number,
): Promise<void> {
  if (sequence <= 0) {
    throw new AuthError('Sequence number must be positive', 401);
  }

  try {
    await ddb.send(
      new UpdateCommand({
        TableName: tableName,
        Key: {
          PK: `TENANT#${tenantId}`,
          SK: `SEQUENCE#${fingerprint}`,
        },
        UpdateExpression: 'SET highestSeq = :new',
        ConditionExpression:
          'attribute_not_exists(highestSeq) OR highestSeq < :new',
        ExpressionAttributeValues: {
          ':new': sequence,
        },
      }),
    );
  } catch (error: unknown) {
    if (
      error &&
      typeof error === 'object' &&
      'name' in error &&
      error.name === 'ConditionalCheckFailedException'
    ) {
      logger.warn('Replay detected: sequence number already seen', {
        tenantId,
        fingerprint,
        sequence,
      });
      throw new AuthError('Replay detected: sequence number already used', 401);
    }
    throw error;
  }
}

export function verifyEd25519Signature(
  publicKeyBase64: string,
  canonicalString: string,
  signatureBase64: string,
): boolean {
  try {
    const publicKeyBuffer = Buffer.from(publicKeyBase64, 'base64');
    const signatureBuffer = Buffer.from(signatureBase64, 'base64');
    const data = Buffer.from(canonicalString);

    // Create Ed25519 public key object from raw bytes
    const keyObject = crypto.createPublicKey({
      key: Buffer.concat([
        // Ed25519 DER prefix for a 32-byte public key
        Buffer.from('302a300506032b6570032100', 'hex'),
        publicKeyBuffer,
      ]),
      format: 'der',
      type: 'spki',
    });

    return crypto.verify(null, data, keyObject, signatureBuffer);
  } catch {
    return false;
  }
}

function tenantIdFromPublicKey(publicKeyBase64: string): string {
  const hash = crypto.createHash('sha256').update(publicKeyBase64).digest('hex');
  return hash.slice(0, 32);
}

export async function authenticateRequest(
  event: {
    requestContext: { http: { method: string; path: string } };
    headers: Record<string, string>;
    body?: string | null;
  },
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<AuthResult> {
  const parsed = parseAuthHeaders(event.headers);
  verifyTimestamp(parsed.timestamp);

  // Look up the public key by querying tenant META records
  // The public key is identified from the request — we need to find which tenant it belongs to
  // For now, extract from legacy header or from a separate header
  const publicKey = extractPublicKey(event.headers);
  const tenantId = tenantIdFromPublicKey(publicKey);
  const fingerprint = fingerprintFromPublicKey(publicKey);

  // Look up the registered public key in DynamoDB
  const result = await ddb.send(
    new QueryCommand({
      TableName: tableName,
      KeyConditionExpression: 'PK = :pk AND SK = :sk',
      ExpressionAttributeValues: {
        ':pk': `TENANT#${tenantId}`,
        ':sk': 'META',
      },
      Limit: 1,
    }),
  );

  if (!result.Items || result.Items.length === 0) {
    throw new AuthError('Unknown public key', 401);
  }

  const tenant = result.Items[0];
  if (tenant['publicKey'] !== publicKey) {
    throw new AuthError('Public key mismatch', 401);
  }

  // Verify the SSH signature against the canonical string (includes sequence)
  const canonicalString = buildCanonicalString(
    event.requestContext.http.method,
    event.requestContext.http.path,
    parsed.timestamp,
    parsed.sequence,
    event.body,
  );

  const valid = verifyEd25519Signature(
    publicKey,
    canonicalString,
    parsed.signature,
  );

  if (!valid) {
    logger.warn('Signature verification failed', { tenantId });
    throw new AuthError('Invalid signature', 401);
  }

  // Check sequence number for replay protection (after signature verification)
  if (parsed.sequence > 0) {
    await checkSequence(ddb, tableName, tenantId, fingerprint, parsed.sequence);
  }

  return { tenantId, publicKey, fingerprint };
}

/**
 * Extract the public key from request headers.
 * New format uses X-ChaosKB-PublicKey header; legacy embeds it in the auth header.
 */
function extractPublicKey(headers: Record<string, string>): string {
  // New header format
  const pubKeyHeader = headers['x-chaoskb-publickey'] || headers['X-ChaosKB-PublicKey'];
  if (pubKeyHeader) return pubKeyHeader;

  // Legacy format: ChaosKB-SSH pubkey=..., ts=..., sig=...
  const authHeader = headers['authorization'] || headers['Authorization'];
  if (authHeader?.startsWith('ChaosKB-SSH ')) {
    const params = authHeader.slice('ChaosKB-SSH '.length);
    for (const part of params.split(', ')) {
      const eqIndex = part.indexOf('=');
      if (eqIndex !== -1 && part.slice(0, eqIndex) === 'pubkey') {
        return part.slice(eqIndex + 1);
      }
    }
  }

  throw new AuthError('Missing public key in request headers', 401);
}
