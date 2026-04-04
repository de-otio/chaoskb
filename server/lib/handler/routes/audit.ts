import * as crypto from 'crypto';
import {
  DynamoDBDocumentClient,
  PutCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { logger } from '../logger.js';

interface HandlerResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
}

export type AuditEventType =
  | 'registered'
  | 'rotation-started'
  | 'rotation-confirmed'
  | 'rotation-completed'
  | 'revoked'
  | 'device-linked'
  | 'device-removed';

export interface AuditEvent {
  eventType: AuditEventType;
  fingerprint: string;
  metadata?: Record<string, unknown>;
}

const TTL_90_DAYS_SECONDS = 90 * 24 * 60 * 60;

/**
 * Write an audit event to DynamoDB.
 *
 * PK: TENANT#{tenantId}, SK: AUDIT#{ISO timestamp}#{random suffix}
 */
export async function logAuditEvent(
  ddb: DynamoDBDocumentClient,
  tableName: string,
  tenantId: string,
  event: AuditEvent,
): Promise<void> {
  const now = new Date().toISOString();
  const suffix = crypto.randomBytes(6).toString('hex');
  const ttl = Math.floor(Date.now() / 1000) + TTL_90_DAYS_SECONDS;

  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `TENANT#${tenantId}`,
        SK: `AUDIT#${now}#${suffix}`,
        eventType: event.eventType,
        fingerprint: event.fingerprint,
        metadata: event.metadata,
        timestamp: now,
        expiresAt: ttl,
      },
    }),
  );

  logger.info('Audit event logged', {
    tenantId,
    eventType: event.eventType,
    fingerprint: event.fingerprint,
  });
}

/**
 * Query all audit log entries for a tenant, sorted by timestamp (ascending).
 */
export async function handleGetAuditLog(
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
        ':prefix': 'AUDIT#',
      },
      ScanIndexForward: true,
    }),
  );

  const events = (result.Items ?? []).map((item) => ({
    eventType: item['eventType'],
    fingerprint: item['fingerprint'],
    metadata: item['metadata'],
    timestamp: item['timestamp'],
  }));

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ events }),
  };
}
