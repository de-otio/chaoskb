import * as crypto from 'crypto';
import {
  DynamoDBDocumentClient,
  PutCommand,
  QueryCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import { logger } from '../logger.js';

interface HandlerResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
}

const JSON_HEADERS = { 'Content-Type': 'application/json' };
const TTL_30_DAYS = 30 * 24 * 60 * 60;

export type NotificationType = 'device_linked' | 'device_revoked' | 'key_rotated';

export interface DeviceInfo {
  hostname?: string;
  platform?: string;
  arch?: string;
  osVersion?: string;
  deviceModel?: string | null;
  location?: string | null;
}

/**
 * Create a notification for a tenant.
 *
 * DynamoDB: PK: TENANT#{tenantId}, SK: NOTIFICATION#{timestamp}#{suffix}
 */
export async function createNotification(
  tenantId: string,
  type: NotificationType,
  deviceInfo: DeviceInfo,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<void> {
  const now = new Date().toISOString();
  const suffix = crypto.randomBytes(4).toString('hex');
  const ttl = Math.floor(Date.now() / 1000) + TTL_30_DAYS;

  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `TENANT#${tenantId}`,
        SK: `NOTIFICATION#${now}#${suffix}`,
        type,
        deviceInfo,
        acknowledged: false,
        timestamp: now,
        expiresAt: ttl,
      },
    }),
  );

  logger.info('Notification created', { tenantId, type });
}

/**
 * GET /v1/notifications — return unacknowledged notifications for tenant.
 */
export async function handleGetNotifications(
  tenantId: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  const result = await ddb.send(
    new QueryCommand({
      TableName: tableName,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :prefix)',
      FilterExpression: 'acknowledged = :false',
      ExpressionAttributeValues: {
        ':pk': `TENANT#${tenantId}`,
        ':prefix': 'NOTIFICATION#',
        ':false': false,
      },
      ScanIndexForward: false, // newest first
      Limit: 50,
    }),
  );

  const notifications = (result.Items ?? []).map((item) => ({
    id: item['SK'],
    type: item['type'],
    deviceInfo: item['deviceInfo'],
    timestamp: item['timestamp'],
  }));

  return {
    statusCode: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify({ notifications }),
  };
}

/**
 * POST /v1/notifications/{id}/dismiss — mark notification as acknowledged.
 */
export async function handleDismissNotification(
  tenantId: string,
  notificationId: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  try {
    await ddb.send(
      new UpdateCommand({
        TableName: tableName,
        Key: {
          PK: `TENANT#${tenantId}`,
          SK: notificationId,
        },
        UpdateExpression: 'SET acknowledged = :true',
        ConditionExpression: 'attribute_exists(PK)',
        ExpressionAttributeValues: {
          ':true': true,
        },
      }),
    );

    return {
      statusCode: 200,
      headers: JSON_HEADERS,
      body: JSON.stringify({ status: 'dismissed' }),
    };
  } catch (err: unknown) {
    if ((err as { name?: string }).name === 'ConditionalCheckFailedException') {
      return {
        statusCode: 404,
        headers: JSON_HEADERS,
        body: JSON.stringify({ error: 'not_found', message: 'Notification not found' }),
      };
    }
    throw err;
  }
}

/**
 * G3: Resolve IP address to approximate location.
 *
 * For Lambda, use a lightweight approach: extract country/region from
 * CloudFront headers if available, otherwise return null.
 * A full MaxMind integration can be added later.
 */
export function resolveIpLocation(headers: Record<string, string>): string | null {
  // CloudFront sets these headers when the distribution is configured
  const country = headers['cloudfront-viewer-country'] || headers['CloudFront-Viewer-Country'];
  const city = headers['cloudfront-viewer-city'] || headers['CloudFront-Viewer-City'];
  const region = headers['cloudfront-viewer-country-region-name'] || headers['CloudFront-Viewer-Country-Region-Name'];

  if (city && country) {
    return region ? `${city}, ${region}, ${country}` : `${city}, ${country}`;
  }
  if (country) {
    return country;
  }
  return null;
}
