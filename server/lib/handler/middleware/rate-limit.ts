import { DynamoDBDocumentClient, UpdateCommand } from '@aws-sdk/lib-dynamodb';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfter?: number;
}

const LIMITS: Record<string, number> = {
  PUT: 100,
  GET: 1000,
  DELETE: 100,
  LIST: 100,
};

const WINDOW_SECONDS = 60;

export async function checkRateLimit(
  tenantId: string,
  operation: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<RateLimitResult> {
  const limit = LIMITS[operation] ?? 300;
  const now = Math.floor(Date.now() / 1000);
  const windowKey = Math.floor(now / WINDOW_SECONDS);
  const ttl = windowKey * WINDOW_SECONDS + WINDOW_SECONDS + 120; // window + 2 min buffer

  const result = await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: {
        PK: `RATE#${tenantId}`,
        SK: `${operation}#${windowKey}`,
      },
      UpdateExpression: 'SET #count = if_not_exists(#count, :zero) + :one, #ttl = :ttl',
      ExpressionAttributeNames: {
        '#count': 'count',
        '#ttl': 'ttl',
      },
      ExpressionAttributeValues: {
        ':zero': 0,
        ':one': 1,
        ':ttl': ttl,
      },
      ReturnValues: 'UPDATED_NEW',
    }),
  );

  const currentCount = (result.Attributes?.['count'] as number) ?? 1;
  const remaining = Math.max(0, limit - currentCount);

  if (currentCount > limit) {
    const windowEnd = (windowKey + 1) * WINDOW_SECONDS;
    const retryAfter = Math.max(1, windowEnd - now);
    return { allowed: false, remaining: 0, retryAfter };
  }

  return { allowed: true, remaining };
}

// Per-IP window sizes: LINK_CONFIRM uses 5-second windows, others use 1-second
const IP_WINDOW_SECONDS: Record<string, number> = {
  LINK_CONFIRM: 5,
  REGISTER_GITHUB: 60,
};

// Per-IP limits: override the default of 1 per window
const IP_LIMITS: Record<string, number> = {
  REGISTER_GITHUB: 5,
};

/**
 * Rate limit by source IP for unauthenticated endpoints (registration, contact).
 * Default: 1 request per second per IP. LINK_CONFIRM: 1 request per 5 seconds.
 */
export async function checkIpRateLimit(
  sourceIp: string,
  operation: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
  limit?: number,
): Promise<RateLimitResult> {
  const effectiveLimit = limit ?? IP_LIMITS[operation] ?? 1;
  const now = Math.floor(Date.now() / 1000);
  const windowSec = IP_WINDOW_SECONDS[operation] ?? 1;
  const windowKey = Math.floor(now / windowSec);
  const ttl = now + 120;

  const result = await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: {
        PK: `RATE#IP#${sourceIp}`,
        SK: `${operation}#${windowKey}`,
      },
      UpdateExpression: 'SET #count = if_not_exists(#count, :zero) + :one, #ttl = :ttl',
      ExpressionAttributeNames: {
        '#count': 'count',
        '#ttl': 'ttl',
      },
      ExpressionAttributeValues: {
        ':zero': 0,
        ':one': 1,
        ':ttl': ttl,
      },
      ReturnValues: 'UPDATED_NEW',
    }),
  );

  const currentCount = (result.Attributes?.['count'] as number) ?? 1;
  if (currentCount > effectiveLimit) {
    const windowEnd = (windowKey + 1) * windowSec;
    const retryAfter = Math.max(1, windowEnd - now);
    return { allowed: false, remaining: 0, retryAfter };
  }
  return { allowed: true, remaining: Math.max(0, effectiveLimit - currentCount) };
}

export function rateLimitHeaders(result: RateLimitResult): Record<string, string> {
  const headers: Record<string, string> = {
    'X-RateLimit-Remaining': String(result.remaining),
  };
  if (!result.allowed && result.retryAfter !== undefined) {
    headers['Retry-After'] = String(result.retryAfter);
  }
  return headers;
}
