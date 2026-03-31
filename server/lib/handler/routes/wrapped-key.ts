import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
} from '@aws-sdk/lib-dynamodb';
import { logger } from '../logger.js';

interface HandlerResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
}

/**
 * Store a wrapped master key blob for the authenticated tenant.
 *
 * The blob is a crypto_box_seal output (Ed25519) or RSA-OAEP KEM+DEM output.
 * The server cannot decrypt it — only the holder of the SSH private key can.
 */
export async function handlePutWrappedKey(
  tenantId: string,
  fingerprint: string,
  rawBody: string | null | undefined,
  isBase64Encoded: boolean,
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

  const bodyBuffer = isBase64Encoded
    ? Buffer.from(rawBody, 'base64')
    : Buffer.from(rawBody, 'utf-8');

  // Max wrapped key size: 4 KB (wrapped master key is typically ~80 bytes for Ed25519, ~512 for RSA)
  if (bodyBuffer.length > 4096) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'invalid_request', message: 'Wrapped key too large (max 4KB)' }),
    };
  }

  const now = new Date().toISOString();

  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `TENANT#${tenantId}`,
        SK: `WRAPPED_KEY#${fingerprint}`,
        data: bodyBuffer.toString('base64'),
        updatedAt: now,
      },
    }),
  );

  logger.info('Wrapped key stored', { tenantId, fingerprint, size: bodyBuffer.length });

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: 'stored' }),
  };
}

/**
 * Retrieve the wrapped master key blob for the authenticated tenant.
 *
 * Returns the blob as application/octet-stream.
 */
export async function handleGetWrappedKey(
  tenantId: string,
  fingerprint: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  const result = await ddb.send(
    new GetCommand({
      TableName: tableName,
      Key: {
        PK: `TENANT#${tenantId}`,
        SK: `WRAPPED_KEY#${fingerprint}`,
      },
    }),
  );

  if (!result.Item) {
    return {
      statusCode: 404,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'not_found', message: 'No wrapped key found for this device' }),
    };
  }

  const data = result.Item['data'] as string;

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/octet-stream' },
    body: data, // base64-encoded wrapped key blob
  };
}
