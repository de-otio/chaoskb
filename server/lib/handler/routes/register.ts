import * as crypto from 'crypto';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { logAuditEvent } from './audit.js';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { logger } from '../logger.js';

interface RegisterRequest {
  publicKey: string;
}

interface HandlerResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
}

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
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'signups_disabled', message: 'New registrations are currently disabled' }),
    };
  }

  // Parse and validate request body
  if (!body) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'invalid_request', message: 'Request body is required' }),
    };
  }

  let request: RegisterRequest;
  try {
    request = JSON.parse(body);
  } catch {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'invalid_request', message: 'Invalid JSON body' }),
    };
  }

  if (!request.publicKey) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'invalid_request', message: 'publicKey is required' }),
    };
  }

  if (!isValidSSHPublicKey(request.publicKey)) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'invalid_request', message: 'Invalid SSH public key format' }),
    };
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

    await logAuditEvent(ddb, tableName, tenantId, {
      eventType: 'registered',
      fingerprint: '',
      metadata: { publicKey: request.publicKey },
    });

    return {
      statusCode: 201,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tenantId, publicKey: request.publicKey }),
    };
  } catch (err: unknown) {
    if ((err as { name?: string }).name === 'ConditionalCheckFailedException') {
      return {
        statusCode: 409,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'already_registered', message: 'This public key is already registered' }),
      };
    }
    throw err;
  }
}
