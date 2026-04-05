import * as crypto from 'crypto';
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  UpdateCommand,
  DeleteCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { logger } from '../logger.js';

interface HandlerResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
}

interface RotateStartRequest {
  newPublicKey: string;
  wrappedBlob: string; // base64-encoded wrapped master key blob
}

/** 48 hours in milliseconds — timeout for rotation confirmation phase. */
const ROTATION_TIMEOUT_MS = 48 * 60 * 60 * 1000;

function fingerprintFromPublicKey(publicKeyBase64: string): string {
  return crypto.createHash('sha256').update(Buffer.from(publicKeyBase64, 'base64')).digest('base64');
}

function tenantIdFromPublicKey(publicKeyBase64: string): string {
  return crypto.createHash('sha256').update(publicKeyBase64).digest('hex').slice(0, 32);
}


function isValidBase64(value: string): boolean {
  if (!value || value.length < 4 || value.length > 8192) return false;
  try {
    const decoded = Buffer.from(value, 'base64');
    return decoded.length > 0;
  } catch {
    return false;
  }
}

/**
 * POST /v1/rotate-start — Phase 1 of two-phase key rotation.
 *
 * Authenticated with the OLD key. Stores the new public key alongside the
 * old key and marks the rotation as started. Both old and new keys are
 * accepted for authentication going forward.
 */
export async function handleRotateStart(
  tenantId: string,
  oldFingerprint: string,
  rawBody: string | null | undefined,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  if (!rawBody) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'invalid_request', message: 'Request body is required' }),
    };
  }

  let request: RotateStartRequest;
  try {
    request = JSON.parse(rawBody);
  } catch {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'invalid_request', message: 'Invalid JSON body' }),
    };
  }

  if (!request.newPublicKey || !isValidBase64(request.newPublicKey)) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'invalid_request', message: 'newPublicKey is required and must be valid base64' }),
    };
  }

  if (!request.wrappedBlob || !isValidBase64(request.wrappedBlob)) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'invalid_request', message: 'wrappedBlob is required and must be valid base64' }),
    };
  }

  // Check for existing rotation in progress
  const existingRotation = await ddb.send(
    new GetCommand({
      TableName: tableName,
      Key: {
        PK: `TENANT#${tenantId}`,
        SK: 'ROTATION',
      },
    }),
  );

  if (existingRotation.Item) {
    return {
      statusCode: 409,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'rotation_in_progress', message: 'A key rotation is already in progress' }),
    };
  }

  const newFingerprint = fingerprintFromPublicKey(request.newPublicKey);
  const now = new Date().toISOString();

  // Store rotation record
  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `TENANT#${tenantId}`,
        SK: 'ROTATION',
        phase: 'started',
        newPublicKey: request.newPublicKey,
        newFingerprint,
        oldFingerprint,
        startedAt: now,
        confirmations: [],
      },
    }),
  );

  // Store the new public key in tenant META so auth middleware accepts both keys
  await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: {
        PK: `TENANT#${tenantId}`,
        SK: 'META',
      },
      UpdateExpression: 'SET newPublicKey = :npk, rotationState = :state, updatedAt = :now',
      ExpressionAttributeValues: {
        ':npk': request.newPublicKey,
        ':state': 'ROTATION_STARTED',
        ':now': now,
      },
    }),
  );

  // Store the wrapped blob for the new key
  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `TENANT#${tenantId}`,
        SK: `WRAPPED_KEY#${newFingerprint}`,
        data: request.wrappedBlob,
        updatedAt: now,
      },
    }),
  );

  // Write a KEY_ALIAS record so auth middleware can resolve the new key's
  // derived tenantId back to this tenant during rotation
  const newKeyTenantId = tenantIdFromPublicKey(request.newPublicKey);
  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `KEY_ALIAS#${newKeyTenantId}`,
        SK: 'META',
        originalTenantId: tenantId,
        newPublicKey: request.newPublicKey,
        createdAt: now,
      },
    }),
  );

  logger.info('Key rotation started', { tenantId, oldFingerprint, newFingerprint });

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      status: 'rotation_started',
      newFingerprint,
      oldFingerprint,
    }),
  };
}

/**
 * POST /v1/rotate-confirm — Phase 2 of two-phase key rotation.
 *
 * Authenticated with the NEW key. Adds the device to the confirmations list.
 * When all registered devices have confirmed (or the 48h timeout has elapsed),
 * completes the rotation by removing the old key and rotation record.
 */
export async function handleRotateConfirm(
  tenantId: string,
  fingerprint: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  // Get the rotation record
  const rotationResult = await ddb.send(
    new GetCommand({
      TableName: tableName,
      Key: {
        PK: `TENANT#${tenantId}`,
        SK: 'ROTATION',
      },
    }),
  );

  if (!rotationResult.Item) {
    return {
      statusCode: 404,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'not_found', message: 'No key rotation in progress' }),
    };
  }

  const rotation = rotationResult.Item;
  const confirmations: string[] = rotation['confirmations'] as string[] ?? [];

  // Add this device fingerprint to confirmations if not already present
  if (!confirmations.includes(fingerprint)) {
    confirmations.push(fingerprint);

    await ddb.send(
      new UpdateCommand({
        TableName: tableName,
        Key: {
          PK: `TENANT#${tenantId}`,
          SK: 'ROTATION',
        },
        UpdateExpression: 'SET confirmations = :c',
        ExpressionAttributeValues: {
          ':c': confirmations,
        },
      }),
    );
  }

  // Check if rotation should be completed:
  // Either all devices confirmed or 48h timeout elapsed
  const startedAt = new Date(rotation['startedAt'] as string).getTime();
  const timeoutReached = Date.now() - startedAt > ROTATION_TIMEOUT_MS;

  // Count registered devices (WRAPPED_KEY# entries = registered devices)
  const deviceResult = await ddb.send(
    new QueryCommand({
      TableName: tableName,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :prefix)',
      ExpressionAttributeValues: {
        ':pk': `TENANT#${tenantId}`,
        ':prefix': 'WRAPPED_KEY#',
      },
      Select: 'COUNT',
    }),
  );

  const deviceCount = deviceResult.Count ?? 0;
  const allConfirmed = confirmations.length >= deviceCount;

  if (allConfirmed || timeoutReached) {
    // Complete the rotation: Phase 2
    await completeRotation(tenantId, rotation, ddb, tableName);

    logger.info('Key rotation completed', {
      tenantId,
      newFingerprint: rotation['newFingerprint'],
      reason: timeoutReached ? 'timeout' : 'all_confirmed',
    });

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: 'rotation_complete',
        confirmations: confirmations.length,
        totalDevices: deviceCount,
      }),
    };
  }

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      status: 'confirmation_recorded',
      confirmations: confirmations.length,
      totalDevices: deviceCount,
    }),
  };
}

/**
 * Complete the rotation by:
 * 1. Updating tenant META with the new public key as primary
 * 2. Deleting old wrapped key blob
 * 3. Deleting the rotation record
 */
async function completeRotation(
  tenantId: string,
  rotation: Record<string, unknown>,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<void> {
  const newPublicKey = rotation['newPublicKey'] as string;
  const oldFingerprint = rotation['oldFingerprint'] as string;
  const now = new Date().toISOString();

  // Update tenant META: replace primary public key, clear rotation state
  await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: {
        PK: `TENANT#${tenantId}`,
        SK: 'META',
      },
      UpdateExpression: 'SET publicKey = :pk, updatedAt = :now REMOVE newPublicKey, rotationState',
      ExpressionAttributeValues: {
        ':pk': newPublicKey,
        ':now': now,
      },
    }),
  );

  // Delete old wrapped key blob
  await ddb.send(
    new DeleteCommand({
      TableName: tableName,
      Key: {
        PK: `TENANT#${tenantId}`,
        SK: `WRAPPED_KEY#${oldFingerprint}`,
      },
    }),
  );

  // Delete rotation record
  await ddb.send(
    new DeleteCommand({
      TableName: tableName,
      Key: {
        PK: `TENANT#${tenantId}`,
        SK: 'ROTATION',
      },
    }),
  );

  // Delete the KEY_ALIAS lookup record for the new key
  const newKeyTenantId = tenantIdFromPublicKey(newPublicKey);
  await ddb.send(
    new DeleteCommand({
      TableName: tableName,
      Key: {
        PK: `KEY_ALIAS#${newKeyTenantId}`,
        SK: 'META',
      },
    }),
  );
}
