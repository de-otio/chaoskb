import {
  DynamoDBDocumentClient,
} from '@aws-sdk/lib-dynamodb';
import { checkRateLimit, rateLimitHeaders } from '../middleware/rate-limit.js';
import { logger } from '../logger.js';

interface HandlerResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
}

export interface SharedProjectMeta {
  name: string;
  role: string;
  owner: string;
  itemCount: number;
}

/**
 * GET /v1/projects/available
 *
 * Query all shared projects this tenant has access to (via MEMBER# records).
 * Returns metadata only: [{ name, role, owner, itemCount }]
 *
 * For now, returns an empty array with the correct shape.
 * Full multi-tenant membership lookup is Phase 2+.
 */
export async function handleListAvailableProjects(
  tenantId: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<HandlerResponse> {
  const rateResult = await checkRateLimit(tenantId, 'GET', ddb, tableName);
  if (!rateResult.allowed) {
    return {
      statusCode: 429,
      headers: { 'Content-Type': 'application/json', ...rateLimitHeaders(rateResult) },
      body: JSON.stringify({ error: 'rate_limited', message: 'Too many requests' }),
    };
  }

  // Phase 2+: Query MEMBER# records for this tenant's public key
  // For now, return an empty array with the correct shape.
  //
  // Future implementation:
  //   const result = await ddb.send(new QueryCommand({
  //     TableName: tableName,
  //     IndexName: 'member-index',
  //     KeyConditionExpression: 'memberPK = :pk',
  //     ExpressionAttributeValues: { ':pk': `KEY#${tenantId}` },
  //   }));
  //   ... map results to SharedProjectMeta ...

  const projects: SharedProjectMeta[] = [];

  logger.info('Listed available projects', {
    tenantId,
    operation: 'LIST_PROJECTS',
    count: projects.length,
  });

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'application/json', ...rateLimitHeaders(rateResult) },
    body: JSON.stringify({ projects }),
  };
}
