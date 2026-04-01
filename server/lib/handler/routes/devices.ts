import * as crypto from 'crypto';
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  DeleteCommand,
  QueryCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import { logger } from '../logger.js';
import { createNotification } from './notifications.js';

interface HandlerResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
}

const JSON_HEADERS = { 'Content-Type': 'application/json' };

/**
 * POST /v1/link-code — authenticated
 *
 * Creates a link code record so a new device can join this tenant.
 * The caller displays the raw code; the server stores only its SHA-256 hash.
 */
export async function handleCreateLinkCode(
  tenantId: string,
  body: string | null | undefined,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  if (!body) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'Request body is required' }),
    };
  }

  let parsed: { codeHash: string };
  try {
    parsed = JSON.parse(body);
  } catch {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'Invalid JSON body' }),
    };
  }

  if (!parsed.codeHash || typeof parsed.codeHash !== 'string') {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'codeHash is required' }),
    };
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + 5 * 60 * 1000).toISOString();
  const ttl = Math.floor(now.getTime() / 1000) + 10 * 60; // DynamoDB TTL: 10 min (generous)

  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `TENANT#${tenantId}`,
        SK: `LINK#${parsed.codeHash}`,
        newPublicKey: null,
        failureCount: 0,
        expiresAt,
        ttl,
      },
    }),
  );

  logger.info('Link code created', { tenantId });

  return {
    statusCode: 201,
    headers: JSON_HEADERS,
    body: JSON.stringify({ status: 'created', expiresAt }),
  };
}

/**
 * POST /v1/link-confirm — unauthenticated (new device)
 *
 * The new device sends the raw link code and its public key.
 * We hash the code, look up the LINK record, validate expiry and failure count,
 * and store the public key for the existing device to pick up.
 */
export async function handleLinkConfirm(
  body: string | null | undefined,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  if (!body) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'Request body is required' }),
    };
  }

  let parsed: { linkCode: string; publicKey: string };
  try {
    parsed = JSON.parse(body);
  } catch {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'Invalid JSON body' }),
    };
  }

  if (!parsed.linkCode || !parsed.publicKey) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'linkCode and publicKey are required' }),
    };
  }

  const codeHash = crypto.createHash('sha256').update(parsed.linkCode).digest('hex');

  // Find the LINK record across tenants — query by SK pattern
  // We need to scan for the link code. Since link codes are short-lived and rare,
  // we use a GSI or scan. For simplicity, the caller must provide tenantId or
  // we search by a known pattern. Actually, the link code hash is unique enough
  // that we store a reverse-lookup record.
  //
  // Alternative approach: query all tenants. But DynamoDB doesn't support that
  // efficiently. Instead, store a top-level LINK_CODE#{hash} -> tenantId mapping.
  //
  // For this implementation, the link-confirm looks up LINK_CODE#{hash} at the
  // table level (PK = LINK_CODE#{hash}).
  const lookupResult = await ddb.send(
    new GetCommand({
      TableName: tableName,
      Key: {
        PK: `LINK_CODE#${codeHash}`,
        SK: 'META',
      },
    }),
  );

  // Fallback: try the tenant-scoped approach by scanning LINK# records
  // For the initial implementation, we use a top-level lookup key.
  // The handleCreateLinkCode also writes this lookup record.

  if (!lookupResult.Item) {
    return {
      statusCode: 404,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'not_found', message: 'Invalid or expired link code' }),
    };
  }

  const tenantId = lookupResult.Item['tenantId'] as string;

  // Fetch the tenant-scoped link record
  const linkResult = await ddb.send(
    new GetCommand({
      TableName: tableName,
      Key: {
        PK: `TENANT#${tenantId}`,
        SK: `LINK#${codeHash}`,
      },
    }),
  );

  if (!linkResult.Item) {
    return {
      statusCode: 404,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'not_found', message: 'Invalid or expired link code' }),
    };
  }

  const linkRecord = linkResult.Item;

  // Check expiry
  if (new Date(linkRecord['expiresAt'] as string) < new Date()) {
    return {
      statusCode: 410,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'expired', message: 'Link code has expired' }),
    };
  }

  // Check failure count
  const failureCount = (linkRecord['failureCount'] as number) ?? 0;
  if (failureCount >= 3) {
    // Delete the record
    await ddb.send(
      new DeleteCommand({
        TableName: tableName,
        Key: { PK: `TENANT#${tenantId}`, SK: `LINK#${codeHash}` },
      }),
    );
    await ddb.send(
      new DeleteCommand({
        TableName: tableName,
        Key: { PK: `LINK_CODE#${codeHash}`, SK: 'META' },
      }),
    );
    return {
      statusCode: 429,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'too_many_failures', message: 'Too many failed attempts' }),
    };
  }

  // Store the new device's public key in the link record
  try {
    await ddb.send(
      new UpdateCommand({
        TableName: tableName,
        Key: {
          PK: `TENANT#${tenantId}`,
          SK: `LINK#${codeHash}`,
        },
        UpdateExpression: 'SET newPublicKey = :pk',
        ConditionExpression: 'attribute_exists(PK)',
        ExpressionAttributeValues: {
          ':pk': parsed.publicKey,
        },
      }),
    );
  } catch (err: unknown) {
    if ((err as { name?: string }).name === 'ConditionalCheckFailedException') {
      return {
        statusCode: 404,
        headers: JSON_HEADERS,
        body: JSON.stringify({ error: 'not_found', message: 'Link code no longer valid' }),
      };
    }
    throw err;
  }

  logger.info('Link confirmed', { tenantId, codeHash: codeHash.slice(0, 8) });

  return {
    statusCode: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify({ status: 'confirmed' }),
  };
}

/**
 * POST /v1/link-code (extended) — also writes the reverse-lookup record.
 *
 * This is a wrapper that ensures both the tenant-scoped LINK# record
 * and the top-level LINK_CODE# lookup record are created.
 */
export async function handleCreateLinkCodeFull(
  tenantId: string,
  body: string | null | undefined,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  if (!body) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'Request body is required' }),
    };
  }

  let parsed: { codeHash: string };
  try {
    parsed = JSON.parse(body);
  } catch {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'Invalid JSON body' }),
    };
  }

  if (!parsed.codeHash || typeof parsed.codeHash !== 'string') {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'codeHash is required' }),
    };
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + 5 * 60 * 1000).toISOString();
  const ttl = Math.floor(now.getTime() / 1000) + 10 * 60;

  // Write the tenant-scoped link record
  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `TENANT#${tenantId}`,
        SK: `LINK#${parsed.codeHash}`,
        newPublicKey: null,
        failureCount: 0,
        expiresAt,
        ttl,
      },
    }),
  );

  // Write the reverse-lookup record (for unauthenticated link-confirm)
  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `LINK_CODE#${parsed.codeHash}`,
        SK: 'META',
        tenantId,
        expiresAt,
        ttl,
      },
    }),
  );

  logger.info('Link code created', { tenantId });

  return {
    statusCode: 201,
    headers: JSON_HEADERS,
    body: JSON.stringify({ status: 'created', expiresAt }),
  };
}

/**
 * GET /v1/link-code/{hash}/status — authenticated
 *
 * Returns { status: 'waiting' } or { status: 'ready', newPublicKey }.
 */
export async function handleGetLinkCodeStatus(
  tenantId: string,
  codeHash: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  const result = await ddb.send(
    new GetCommand({
      TableName: tableName,
      Key: {
        PK: `TENANT#${tenantId}`,
        SK: `LINK#${codeHash}`,
      },
    }),
  );

  if (!result.Item) {
    return {
      statusCode: 404,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'not_found', message: 'Link code not found' }),
    };
  }

  const newPublicKey = result.Item['newPublicKey'] as string | null;

  if (newPublicKey) {
    return {
      statusCode: 200,
      headers: JSON_HEADERS,
      body: JSON.stringify({ status: 'ready', newPublicKey }),
    };
  }

  return {
    statusCode: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify({ status: 'waiting' }),
  };
}

/**
 * GET /v1/devices — authenticated
 *
 * Lists all registered devices (KEY#{fingerprint} items) for the tenant.
 */
export async function handleListDevices(
  tenantId: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  const result = await ddb.send(
    new QueryCommand({
      TableName: tableName,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :prefix)',
      ExpressionAttributeValues: {
        ':pk': `TENANT#${tenantId}`,
        ':prefix': 'KEY#',
      },
    }),
  );

  const devices = (result.Items ?? []).map((item) => ({
    fingerprint: (item['SK'] as string).replace('KEY#', ''),
    registeredAt: item['registeredAt'] as string,
    publicKey: item['publicKey'] as string | undefined,
  }));

  return {
    statusCode: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify({ devices }),
  };
}

/**
 * DELETE /v1/devices/{fingerprint} — authenticated
 *
 * Removes the KEY# item and WRAPPED_KEY# item for the given device.
 */
export async function handleDeleteDevice(
  tenantId: string,
  fingerprint: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  // Delete the KEY# record
  await ddb.send(
    new DeleteCommand({
      TableName: tableName,
      Key: {
        PK: `TENANT#${tenantId}`,
        SK: `KEY#${fingerprint}`,
      },
    }),
  );

  // Delete the WRAPPED_KEY# record
  await ddb.send(
    new DeleteCommand({
      TableName: tableName,
      Key: {
        PK: `TENANT#${tenantId}`,
        SK: `WRAPPED_KEY#${fingerprint}`,
      },
    }),
  );

  // Create revocation notification for remaining devices
  await createNotification(tenantId, 'device_revoked', {
    hostname: fingerprint,
  }, ddb, tableName);

  logger.info('Device removed', { tenantId, fingerprint });

  return {
    statusCode: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify({ status: 'deleted' }),
  };
}
