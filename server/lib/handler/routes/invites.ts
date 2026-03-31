import * as crypto from 'crypto';
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  UpdateCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { logger } from '../logger.js';
import { logAuditEvent } from './audit.js';

interface HandlerResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
}

const JSON_HEADERS = { 'Content-Type': 'application/json' };

const FOURTEEN_DAYS_MS = 14 * 24 * 60 * 60 * 1000;
const FOURTEEN_DAYS_SECONDS = 14 * 24 * 60 * 60;
const TWENTY_FOUR_HOURS_SECONDS = 24 * 60 * 60;

const HOUR_SECONDS = 3600;
const DAY_SECONDS = 86400;
const HOURLY_INVITE_LIMIT = 10;
const DAILY_INVITE_LIMIT = 50;
const MAX_PENDING_INVITES = 20;

/**
 * Check sender rate limits for invite creation.
 * Uses DynamoDB counters with hourly and daily windows.
 */
async function checkInviteRateLimit(
  senderFingerprint: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<{ allowed: boolean; message?: string }> {
  const now = Math.floor(Date.now() / 1000);
  const hourWindow = Math.floor(now / HOUR_SECONDS);
  const dayWindow = Math.floor(now / DAY_SECONDS);

  // Check hourly limit
  const hourResult = await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: {
        PK: `RATE#INVITE#${senderFingerprint}`,
        SK: `HOUR#${hourWindow}`,
      },
      UpdateExpression: 'SET #count = if_not_exists(#count, :zero) + :one, #ttl = :ttl',
      ExpressionAttributeNames: {
        '#count': 'count',
        '#ttl': 'ttl',
      },
      ExpressionAttributeValues: {
        ':zero': 0,
        ':one': 1,
        ':ttl': hourWindow * HOUR_SECONDS + HOUR_SECONDS + 120,
      },
      ReturnValues: 'UPDATED_NEW',
    }),
  );

  const hourlyCount = (hourResult.Attributes?.['count'] as number) ?? 1;
  if (hourlyCount > HOURLY_INVITE_LIMIT) {
    return { allowed: false, message: 'Hourly invite limit exceeded (max 10/hour)' };
  }

  // Check daily limit
  const dayResult = await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: {
        PK: `RATE#INVITE#${senderFingerprint}`,
        SK: `DAY#${dayWindow}`,
      },
      UpdateExpression: 'SET #count = if_not_exists(#count, :zero) + :one, #ttl = :ttl',
      ExpressionAttributeNames: {
        '#count': 'count',
        '#ttl': 'ttl',
      },
      ExpressionAttributeValues: {
        ':zero': 0,
        ':one': 1,
        ':ttl': dayWindow * DAY_SECONDS + DAY_SECONDS + 120,
      },
      ReturnValues: 'UPDATED_NEW',
    }),
  );

  const dailyCount = (dayResult.Attributes?.['count'] as number) ?? 1;
  if (dailyCount > DAILY_INVITE_LIMIT) {
    return { allowed: false, message: 'Daily invite limit exceeded (max 50/day)' };
  }

  return { allowed: true };
}

/**
 * Check that the recipient doesn't have too many pending invites.
 */
async function checkRecipientPendingCount(
  recipientFingerprint: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<boolean> {
  const result = await ddb.send(
    new QueryCommand({
      TableName: tableName,
      IndexName: 'GSI-RecipientFingerprint',
      KeyConditionExpression: 'recipientFingerprint = :fp',
      FilterExpression: '#status = :pending',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: {
        ':fp': recipientFingerprint,
        ':pending': 'pending',
      },
      Select: 'COUNT',
    }),
  );

  return (result.Count ?? 0) < MAX_PENDING_INVITES;
}

/**
 * POST /v1/invites - Create an invite
 */
export async function handleCreateInvite(
  tenantId: string,
  fingerprint: string,
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

  let parsed: {
    recipientFingerprint: string;
    projectTenantId: string;
    encryptedPayload: string;
    role: string;
  };
  try {
    parsed = JSON.parse(body);
  } catch {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'Invalid JSON body' }),
    };
  }

  if (
    !parsed.recipientFingerprint ||
    !parsed.projectTenantId ||
    !parsed.encryptedPayload ||
    !parsed.role
  ) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({
        error: 'invalid_request',
        message: 'recipientFingerprint, projectTenantId, encryptedPayload, and role are required',
      }),
    };
  }

  // Validate encryptedPayload is valid base64
  if (!/^[A-Za-z0-9+/]+=*$/.test(parsed.encryptedPayload)) {
    return {
      statusCode: 400,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'invalid_request', message: 'encryptedPayload must be valid base64' }),
    };
  }

  // Check sender rate limits
  const rateCheck = await checkInviteRateLimit(fingerprint, ddb, tableName);
  if (!rateCheck.allowed) {
    return {
      statusCode: 429,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'rate_limited', message: rateCheck.message }),
    };
  }

  // Check recipient pending count
  const recipientOk = await checkRecipientPendingCount(
    parsed.recipientFingerprint,
    ddb,
    tableName,
  );
  if (!recipientOk) {
    return {
      statusCode: 409,
      headers: JSON_HEADERS,
      body: JSON.stringify({
        error: 'recipient_limit',
        message: 'Recipient has too many pending invites',
      }),
    };
  }

  const inviteId = crypto.randomUUID();
  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + FOURTEEN_DAYS_MS).toISOString();
  const ttl = Math.floor(now.getTime() / 1000) + FOURTEEN_DAYS_SECONDS;

  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `INVITE#${inviteId}`,
        SK: 'META',
        inviteId,
        status: 'pending',
        senderFingerprint: fingerprint,
        recipientFingerprint: parsed.recipientFingerprint,
        projectTenantId: parsed.projectTenantId,
        encryptedPayload: parsed.encryptedPayload,
        role: parsed.role,
        createdAt,
        expiresAt,
        ttl,
      },
    }),
  );

  await logAuditEvent(ddb, tableName, tenantId, {
    eventType: 'invite-created' as any,
    fingerprint,
    metadata: {
      inviteId,
      recipientFingerprint: parsed.recipientFingerprint,
      projectTenantId: parsed.projectTenantId,
      role: parsed.role,
    },
  });

  logger.info('Invite created', { tenantId, inviteId });

  return {
    statusCode: 201,
    headers: JSON_HEADERS,
    body: JSON.stringify({ inviteId, status: 'pending' }),
  };
}

/**
 * GET /v1/invites - List pending invites for the authenticated user
 */
export async function handleListInvites(
  tenantId: string,
  fingerprint: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  const now = new Date().toISOString();

  const result = await ddb.send(
    new QueryCommand({
      TableName: tableName,
      IndexName: 'GSI-RecipientFingerprint',
      KeyConditionExpression: 'recipientFingerprint = :fp',
      FilterExpression: '#status = :pending AND expiresAt > :now',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: {
        ':fp': fingerprint,
        ':pending': 'pending',
        ':now': now,
      },
    }),
  );

  const invites = (result.Items ?? []).map((item) => ({
    inviteId: item['inviteId'],
    senderFingerprint: item['senderFingerprint'],
    projectTenantId: item['projectTenantId'],
    role: item['role'],
    createdAt: item['createdAt'],
  }));

  return {
    statusCode: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify({ invites }),
  };
}

/**
 * POST /v1/invites/{id}/accept - Accept an invite
 */
export async function handleAcceptInvite(
  tenantId: string,
  fingerprint: string,
  inviteId: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  const result = await ddb.send(
    new GetCommand({
      TableName: tableName,
      Key: {
        PK: `INVITE#${inviteId}`,
        SK: 'META',
      },
    }),
  );

  if (!result.Item) {
    return {
      statusCode: 404,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'not_found', message: 'Invite not found' }),
    };
  }

  const invite = result.Item;

  // Check recipient matches
  if (invite['recipientFingerprint'] !== fingerprint) {
    return {
      statusCode: 403,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'forbidden', message: 'Not authorized to accept this invite' }),
    };
  }

  // Idempotent: already accepted
  if (invite['status'] === 'accepted') {
    return {
      statusCode: 200,
      headers: JSON_HEADERS,
      body: JSON.stringify({
        status: 'already_accepted',
        encryptedPayload: invite['encryptedPayload'],
        projectTenantId: invite['projectTenantId'],
      }),
    };
  }

  // Check status is pending
  if (invite['status'] !== 'pending') {
    return {
      statusCode: 409,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'conflict', message: `Invite is ${invite['status']}` }),
    };
  }

  // Check not expired
  if (new Date(invite['expiresAt'] as string) < new Date()) {
    return {
      statusCode: 410,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'expired', message: 'Invite has expired' }),
    };
  }

  const now = new Date();
  const acceptedAt = now.toISOString();
  // Schedule cleanup: TTL 24 hours after acceptance
  const cleanupTtl = Math.floor(now.getTime() / 1000) + TWENTY_FOUR_HOURS_SECONDS;

  await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: {
        PK: `INVITE#${inviteId}`,
        SK: 'META',
      },
      UpdateExpression: 'SET #status = :accepted, acceptedAt = :acceptedAt, #ttl = :ttl',
      ExpressionAttributeNames: {
        '#status': 'status',
        '#ttl': 'ttl',
      },
      ExpressionAttributeValues: {
        ':accepted': 'accepted',
        ':acceptedAt': acceptedAt,
        ':ttl': cleanupTtl,
      },
    }),
  );

  await logAuditEvent(ddb, tableName, tenantId, {
    eventType: 'invite-accepted' as any,
    fingerprint,
    metadata: {
      inviteId,
      projectTenantId: invite['projectTenantId'],
    },
  });

  logger.info('Invite accepted', { tenantId, inviteId });

  return {
    statusCode: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify({
      status: 'accepted',
      encryptedPayload: invite['encryptedPayload'],
      projectTenantId: invite['projectTenantId'],
    }),
  };
}

/**
 * POST /v1/invites/{id}/decline - Decline an invite
 */
export async function handleDeclineInvite(
  tenantId: string,
  fingerprint: string,
  inviteId: string,
  body: string | null | undefined,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  const result = await ddb.send(
    new GetCommand({
      TableName: tableName,
      Key: {
        PK: `INVITE#${inviteId}`,
        SK: 'META',
      },
    }),
  );

  if (!result.Item) {
    return {
      statusCode: 404,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'not_found', message: 'Invite not found' }),
    };
  }

  const invite = result.Item;

  // Check recipient matches
  if (invite['recipientFingerprint'] !== fingerprint) {
    return {
      statusCode: 403,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'forbidden', message: 'Not authorized to decline this invite' }),
    };
  }

  // Check status is pending
  if (invite['status'] !== 'pending') {
    return {
      statusCode: 409,
      headers: JSON_HEADERS,
      body: JSON.stringify({ error: 'conflict', message: `Invite is already ${invite['status']}` }),
    };
  }

  await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: {
        PK: `INVITE#${inviteId}`,
        SK: 'META',
      },
      UpdateExpression: 'SET #status = :declined, declinedAt = :declinedAt',
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExpressionAttributeValues: {
        ':declined': 'declined',
        ':declinedAt': new Date().toISOString(),
      },
    }),
  );

  // Handle optional block
  let parsed: { block?: boolean; senderFingerprint?: string } = {};
  if (body) {
    try {
      parsed = JSON.parse(body);
    } catch {
      // Ignore invalid JSON in decline body — blocking is optional
    }
  }

  if (parsed.block && parsed.senderFingerprint) {
    await ddb.send(
      new PutCommand({
        TableName: tableName,
        Item: {
          PK: `TENANT#${tenantId}`,
          SK: `BLOCK#${parsed.senderFingerprint}`,
          blockedAt: new Date().toISOString(),
        },
      }),
    );
    logger.info('Sender blocked', { tenantId, senderFingerprint: parsed.senderFingerprint });
  }

  await logAuditEvent(ddb, tableName, tenantId, {
    eventType: 'invite-declined' as any,
    fingerprint,
    metadata: {
      inviteId,
      blocked: parsed.block ?? false,
    },
  });

  logger.info('Invite declined', { tenantId, inviteId });

  return {
    statusCode: 200,
    headers: JSON_HEADERS,
    body: JSON.stringify({ status: 'declined' }),
  };
}
