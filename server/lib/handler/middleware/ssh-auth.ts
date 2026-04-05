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

/**
 * Read an SSH wire-format string (uint32 length + bytes) from a buffer.
 */
function readSSHString(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const len = buf.readUInt32BE(offset);
  return { data: buf.subarray(offset + 4, offset + 4 + len), next: offset + 4 + len };
}

// --- DER / ASN.1 encoding helpers ---

function derLength(length: number): Buffer {
  if (length < 128) return Buffer.from([length]);
  if (length < 256) return Buffer.from([0x81, length]);
  const buf = Buffer.alloc(3);
  buf[0] = 0x82;
  buf.writeUInt16BE(length, 1);
  return buf;
}

function derWrap(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

function derSequence(...items: Buffer[]): Buffer {
  return derWrap(0x30, Buffer.concat(items));
}

function derInteger(data: Buffer): Buffer {
  // Strip leading zeros, but keep padding zero if high bit is set
  let start = 0;
  while (start < data.length - 1 && data[start] === 0 && !(data[start + 1] & 0x80)) {
    start++;
  }
  let buf = data.subarray(start);
  if (buf[0] & 0x80) {
    buf = Buffer.concat([Buffer.from([0x00]), buf]);
  }
  return derWrap(0x02, buf);
}

function derBitString(data: Buffer): Buffer {
  return derWrap(0x03, Buffer.concat([Buffer.from([0x00]), data]));
}

function derOid(encoded: Buffer): Buffer {
  return derWrap(0x06, encoded);
}

const DER_NULL = Buffer.from([0x05, 0x00]);

/**
 * Build a crypto.KeyObject from an SSH public key blob (base64-encoded wire format).
 * Supports ssh-ed25519, ssh-rsa, and ecdsa-sha2-nistp{256,384,521}.
 */
function createPublicKeyFromSSHBlob(publicKeyBase64: string): crypto.KeyObject {
  const blob = Buffer.from(publicKeyBase64, 'base64');
  const { data: keyTypeBytes, next: off1 } = readSSHString(blob, 0);
  const keyType = keyTypeBytes.toString('utf-8');

  if (keyType === 'ssh-ed25519') {
    const { data: rawKey } = readSSHString(blob, off1);
    const spki = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      rawKey,
    ]);
    return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
  }

  if (keyType === 'ssh-rsa') {
    const { data: e, next: off2 } = readSSHString(blob, off1);
    const { data: n } = readSSHString(blob, off2);
    // OID 1.2.840.113549.1.1.1 (rsaEncryption)
    const rsaOid = derOid(Buffer.from('2a864886f70d010101', 'hex'));
    const algorithmId = derSequence(rsaOid, DER_NULL);
    const rsaPublicKey = derSequence(derInteger(n), derInteger(e));
    return crypto.createPublicKey({
      key: derSequence(algorithmId, derBitString(rsaPublicKey)),
      format: 'der',
      type: 'spki',
    });
  }

  if (keyType.startsWith('ecdsa-sha2-')) {
    const { data: curveNameBytes, next: off2 } = readSSHString(blob, off1);
    const { data: point } = readSSHString(blob, off2);
    const curve = curveNameBytes.toString('utf-8');
    const curveOids: Record<string, string> = {
      'nistp256': '2a8648ce3d030107',   // 1.2.840.10045.3.1.7
      'nistp384': '2b81040022',          // 1.3.132.0.34
      'nistp521': '2b81040023',          // 1.3.132.0.35
    };
    const oidHex = curveOids[curve];
    if (!oidHex) throw new Error(`Unsupported ECDSA curve: ${curve}`);
    // OID 1.2.840.10045.2.1 (ecPublicKey)
    const ecOid = derOid(Buffer.from('2a8648ce3d0201', 'hex'));
    const algorithmId = derSequence(ecOid, derOid(Buffer.from(oidHex, 'hex')));
    return crypto.createPublicKey({
      key: derSequence(algorithmId, derBitString(point)),
      format: 'der',
      type: 'spki',
    });
  }

  throw new Error(`Unsupported SSH key type: ${keyType}`);
}

/**
 * Verify an SSH signature against a canonical string.
 * The public key is the base64-encoded SSH wire-format blob from the request header.
 * Supports Ed25519, RSA (PKCS#1 v1.5 SHA-256), and ECDSA (SHA-256).
 */
export function verifySSHSignature(
  publicKeyBase64: string,
  canonicalString: string,
  signatureBase64: string,
): boolean {
  try {
    const keyObject = createPublicKeyFromSSHBlob(publicKeyBase64);
    const signatureBuffer = Buffer.from(signatureBase64, 'base64');
    const data = Buffer.from(canonicalString);
    // Ed25519/Ed448 infer the algorithm; RSA and ECDSA use SHA-256
    const algorithm =
      keyObject.asymmetricKeyType === 'ed25519' || keyObject.asymmetricKeyType === 'ed448'
        ? null
        : 'sha256';
    return crypto.verify(algorithm, data, keyObject, signatureBuffer);
  } catch {
    return false;
  }
}

/** @deprecated Use verifySSHSignature instead. */
export const verifyEd25519Signature = verifySSHSignature;

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

  let resolvedTenantId = tenantId;

  if (!result.Items || result.Items.length === 0) {
    // Primary tenant lookup failed — check if this key is a rotation newPublicKey.
    // rotate-start writes a KEY_ALIAS# record that maps the new key's derived tenantId
    // back to the original tenant during rotation.
    const aliasResult = await ddb.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: 'PK = :pk AND SK = :sk',
        ExpressionAttributeValues: {
          ':pk': `KEY_ALIAS#${tenantId}`,
          ':sk': 'META',
        },
        Limit: 1,
      }),
    );

    if (!aliasResult.Items || aliasResult.Items.length === 0) {
      // Perform a dummy signature verification to equalize timing
      const dummyKey = Buffer.alloc(32, 0x01).toString('base64');
      try {
        verifySSHSignature(dummyKey, 'dummy', 'dummy');
      } catch {
        // Expected to fail — timing equalization only
      }
      throw new AuthError('Unknown public key', 401);
    }

    // Resolve to the original tenant
    resolvedTenantId = aliasResult.Items[0]['originalTenantId'] as string;

    // Re-fetch the original tenant META
    const originalResult = await ddb.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: 'PK = :pk AND SK = :sk',
        ExpressionAttributeValues: {
          ':pk': `TENANT#${resolvedTenantId}`,
          ':sk': 'META',
        },
        Limit: 1,
      }),
    );

    if (!originalResult.Items || originalResult.Items.length === 0) {
      throw new AuthError('Unknown public key', 401);
    }

    const originalTenant = originalResult.Items[0];
    const newPk = originalTenant['newPublicKey'] as string | undefined;
    if (!newPk || originalTenant['rotationState'] !== 'ROTATION_STARTED') {
      throw new AuthError('Unknown public key', 401);
    }
    const storedNewKey = Buffer.from(newPk);
    const suppliedKey = Buffer.from(publicKey);
    if (suppliedKey.length !== storedNewKey.length || !crypto.timingSafeEqual(suppliedKey, storedNewKey)) {
      throw new AuthError('Public key mismatch', 401);
    }
  } else {
    const tenant = result.Items[0];
    const storedKey = Buffer.from(tenant['publicKey'] as string);
    const suppliedKey = Buffer.from(publicKey);
    if (storedKey.length !== suppliedKey.length || !crypto.timingSafeEqual(storedKey, suppliedKey)) {
      // Primary key doesn't match — check if this key is the newPublicKey during rotation
      const newPk = tenant['newPublicKey'] as string | undefined;
      if (!newPk || tenant['rotationState'] !== 'ROTATION_STARTED') {
        throw new AuthError('Public key mismatch', 401);
      }
      const storedNewKey = Buffer.from(newPk);
      if (suppliedKey.length !== storedNewKey.length || !crypto.timingSafeEqual(suppliedKey, storedNewKey)) {
        throw new AuthError('Public key mismatch', 401);
      }
    }
  }

  // Verify the SSH signature against the canonical string (includes sequence)
  const canonicalString = buildCanonicalString(
    event.requestContext.http.method,
    event.requestContext.http.path,
    parsed.timestamp,
    parsed.sequence,
    event.body,
  );

  const valid = verifySSHSignature(
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
    await checkSequence(ddb, tableName, resolvedTenantId, fingerprint, parsed.sequence);
  }

  return { tenantId: resolvedTenantId, publicKey, fingerprint };
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
