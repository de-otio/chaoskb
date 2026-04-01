import * as crypto from 'crypto';
import { DynamoDBDocumentClient, PutCommand, GetCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import { logAuditEvent } from './audit.js';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { logger } from '../logger.js';
import {
  verifyKeyOnGitHub,
  storeGitHubAssociation,
  storeGitHubReverseLookup,
  findTenantByGitHub,
  GitHubVerificationError,
} from './github.js';

interface RegisterRequest {
  publicKey: string;
  signedChallenge: string;
  challengeNonce: string;
  github?: string;
}

interface HandlerResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
}

const CHALLENGE_EXPIRY_SECONDS = 60;
const JSON_HEADERS = { 'Content-Type': 'application/json' };

let cachedSignupsEnabled: { value: boolean; expiresAt: number } | null = null;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

const ssmClient = new SSMClient({});

export async function checkSignupsEnabled(paramName: string): Promise<boolean> {
  const now = Date.now();
  if (cachedSignupsEnabled && now < cachedSignupsEnabled.expiresAt) {
    return cachedSignupsEnabled.value;
  }

  try {
    const result = await ssmClient.send(
      new GetParameterCommand({ Name: paramName }),
    );
    const value = result.Parameter?.Value !== 'false';
    cachedSignupsEnabled = { value, expiresAt: now + CACHE_TTL_MS };
    return value;
  } catch (err) {
    logger.error('Failed to fetch signups-enabled parameter', { error: String(err) });
    // Default to enabled if parameter fetch fails
    return true;
  }
}

// Exported for testing
export function _resetSignupsCache(): void {
  cachedSignupsEnabled = null;
}

function tenantIdFromPublicKey(publicKeyBase64: string): string {
  const hash = crypto.createHash('sha256').update(publicKeyBase64).digest('hex');
  return hash.slice(0, 32);
}

function isValidSSHPublicKey(publicKey: string): boolean {
  // Basic validation: must be base64 and reasonable length
  if (!publicKey || publicKey.length < 16 || publicKey.length > 2048) {
    return false;
  }
  try {
    const decoded = Buffer.from(publicKey, 'base64');
    return decoded.length > 0 && publicKey === decoded.toString('base64');
  } catch {
    return false;
  }
}

/**
 * Verify an Ed25519 signature of a challenge nonce against a public key.
 * The signed data is: "chaoskb-register\n" + nonce (base64).
 */
function verifyRegistrationSignature(
  publicKeyBase64: string,
  nonce: string,
  signatureBase64: string,
): boolean {
  try {
    const publicKeyBuffer = Buffer.from(publicKeyBase64, 'base64');
    const signatureBuffer = Buffer.from(signatureBase64, 'base64');
    const data = Buffer.from(`chaoskb-register\n${nonce}`);

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

/**
 * GET /v1/register/challenge — generate a registration challenge nonce.
 *
 * Returns a 32-byte random nonce (base64-encoded) that must be signed by the
 * client's SSH private key and submitted with the registration request.
 * Challenge expires after 60 seconds and is single-use.
 */
export async function handleChallenge(
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  const nonce = crypto.randomBytes(32).toString('base64');
  const now = Math.floor(Date.now() / 1000);
  const ttl = now + CHALLENGE_EXPIRY_SECONDS + 60; // DynamoDB TTL: generous buffer
  const expiresAt = new Date((now + CHALLENGE_EXPIRY_SECONDS) * 1000).toISOString();

  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `CHALLENGE#${nonce}`,
        SK: 'META',
        expiresAt,
        ttl,
      },
    }),
  );

  logger.info('Registration challenge created');

  return {
    statusCode: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify({ challenge: nonce, expiresAt }),
  };
}

export async function handleRegister(
  body: string | null | undefined,
  ddb: DynamoDBDocumentClient,
  tableName: string,
  signupsParamName: string,
): Promise<HandlerResponse> {
  // Check if signups are enabled
  const signupsEnabled = await checkSignupsEnabled(signupsParamName);
  if (!signupsEnabled) {
    return {
      statusCode: 403,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'signups_disabled', message: 'New registrations are currently disabled' }),
    };
  }

  // Parse and validate request body
  if (!body) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'Request body is required' }),
    };
  }

  let request: RegisterRequest;
  try {
    request = JSON.parse(body);
  } catch {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'Invalid JSON body' }),
    };
  }

  if (!request.publicKey) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'publicKey is required' }),
    };
  }

  if (!request.signedChallenge || !request.challengeNonce) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'signedChallenge and challengeNonce are required' }),
    };
  }

  if (!isValidSSHPublicKey(request.publicKey)) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'Invalid SSH public key format' }),
    };
  }

  // Look up and consume the challenge nonce (single-use)
  const challengeResult = await ddb.send(
    new GetCommand({
      TableName: tableName,
      Key: {
        PK: `CHALLENGE#${request.challengeNonce}`,
        SK: 'META',
      },
    }),
  );

  if (!challengeResult.Item) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_challenge', message: 'Challenge not found or already used' }),
    };
  }

  // Check challenge expiry
  if (new Date(challengeResult.Item['expiresAt'] as string) < new Date()) {
    // Clean up expired challenge
    await ddb.send(
      new DeleteCommand({
        TableName: tableName,
        Key: { PK: `CHALLENGE#${request.challengeNonce}`, SK: 'META' },
      }),
    );
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'challenge_expired', message: 'Challenge has expired' }),
    };
  }

  // Consume the challenge (delete it — single-use)
  await ddb.send(
    new DeleteCommand({
      TableName: tableName,
      Key: { PK: `CHALLENGE#${request.challengeNonce}`, SK: 'META' },
    }),
  );

  // Verify the SSH signature of the challenge nonce against the public key
  const validSignature = verifyRegistrationSignature(
    request.publicKey,
    request.challengeNonce,
    request.signedChallenge,
  );

  if (!validSignature) {
    logger.warn('Registration signature verification failed');
    return {
      statusCode: 401,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_signature', message: 'Challenge signature verification failed' }),
    };
  }

  // GitHub verification (if --github was provided)
  if (request.github) {
    try {
      const keyOnGitHub = await verifyKeyOnGitHub(request.publicKey, request.github);
      if (!keyOnGitHub) {
        return {
          statusCode: 400,
          headers: JSON_HEADERS,
          body: JSON.stringify({
            error: 'github_key_not_found',
            message: `Public key not found on GitHub account "${request.github}"`,
          }),
        };
      }
    } catch (err) {
      if (err instanceof GitHubVerificationError) {
        return {
          statusCode: 400,
          headers: JSON_HEADERS,
          body: JSON.stringify({ error: err.code, message: err.message }),
        };
      }
      throw err;
    }

    // Check if an existing tenant is associated with this GitHub username (auto-link)
    const existingTenantId = await findTenantByGitHub(request.github, ddb, tableName);
    if (existingTenantId) {
      logger.info('GitHub auto-link: existing tenant found', {
        existingTenantId,
        github: request.github,
      });
      return {
        statusCode: 200,
        headers: JSON_HEADERS,
        body: JSON.stringify({
          status: 'auto_linked',
          tenantId: existingTenantId,
          github: request.github,
        }),
      };
    }
  }

  const tenantId = tenantIdFromPublicKey(request.publicKey);
  const now = new Date().toISOString();

  try {
    await ddb.send(
      new PutCommand({
        TableName: tableName,
        Item: {
          PK: `TENANT#${tenantId}`,
          SK: 'META',
          publicKey: request.publicKey,
          createdAt: now,
          updatedAt: now,
          storageUsedBytes: 0,
        },
        ConditionExpression: 'attribute_not_exists(SK)',
      }),
    );

    logger.info('Tenant registered', { tenantId, operation: 'register' });

    // Store GitHub association if provided
    if (request.github) {
      await storeGitHubAssociation(tenantId, request.github, ddb, tableName);
      await storeGitHubReverseLookup(request.github, tenantId, ddb, tableName);
    }

    await logAuditEvent(ddb, tableName, tenantId, {
      eventType: 'registered',
      fingerprint: '',
      metadata: {
        publicKey: request.publicKey,
        ...(request.github && { github: request.github }),
      },
    });

    return {
      statusCode: 201,
      headers: JSON_HEADERS,
      body: JSON.stringify({
        tenantId,
        publicKey: request.publicKey,
        ...(request.github && { github: request.github }),
      }),
    };
  } catch (err: unknown) {
    if ((err as { name?: string }).name === 'ConditionalCheckFailedException') {
      return {
        statusCode: 409,
        headers: JSON_HEADERS,
        body: JSON.stringify({ error: 'already_registered', message: 'This public key is already registered' }),
      };
    }
    throw err;
  }
}
