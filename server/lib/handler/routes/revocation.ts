import {
  DynamoDBDocumentClient,
  QueryCommand,
  BatchWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { logAuditEvent } from './audit.js';
import { logger } from '../logger.js';

interface HandlerResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
}

/**
 * Emergency revocation: delete all KEY#, WRAPPED_KEY#, ROTATION, and SEQUENCE# items
 * for a tenant, then log an audit event.
 */
export async function handleRevokeAll(
  tenantId: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  const pk = `TENANT#${tenantId}`;

  // Query all items in the tenant partition
  const result = await ddb.send(
    new QueryCommand({
      TableName: tableName,
      KeyConditionExpression: 'PK = :pk',
      ExpressionAttributeValues: {
        ':pk': pk,
      },
      ProjectionExpression: 'PK, SK',
    }),
  );

  const allItems = result.Items ?? [];

  // Filter to revocable SK prefixes
  const toDelete = allItems.filter((item) => {
    const sk = item['SK'] as string;
    return (
      sk.startsWith('KEY#') ||
      sk.startsWith('WRAPPED_KEY#') ||
      sk === 'ROTATION' ||
      sk.startsWith('SEQUENCE#')
    );
  });

  // Batch delete in groups of 25
  for (let i = 0; i < toDelete.length; i += 25) {
    const batch = toDelete.slice(i, i + 25);
    await ddb.send(
      new BatchWriteCommand({
        RequestItems: {
          [tableName]: batch.map((item) => ({
            DeleteRequest: {
              Key: { PK: item['PK'], SK: item['SK'] },
            },
          })),
        },
      }),
    );
  }

  logger.info('Emergency revocation completed', {
    tenantId,
    deletedItems: toDelete.length,
  });

  // Log audit event
  await logAuditEvent(ddb, tableName, tenantId, {
    eventType: 'revoked',
    fingerprint: 'all',
    metadata: { deletedItems: toDelete.length },
  });

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      status: 'revoked',
      message: 'All devices revoked. Re-register with a new SSH key.',
    }),
  };
}
