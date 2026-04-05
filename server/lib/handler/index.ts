import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { logger } from './logger.js';
import { authenticateRequest, AuthError } from './middleware/ssh-auth.js';
import { checkIpRateLimit, rateLimitHeaders } from './middleware/rate-limit.js';
import { handleHealth } from './routes/health.js';
import { handleRegister, handleChallenge } from './routes/register.js';
import {
  handlePutBlob,
  handleGetBlob,
  handleDeleteBlob,
  handleListBlobs,
  handleCountBlobs,
} from './routes/blobs.js';
import { handleRestore } from './routes/restore.js';
import { handleCreateTenant, handleListTenants, handleDeleteTenant } from './routes/tenants.js';
import { handleExport } from './routes/export.js';
import { handlePutWrappedKey, handleGetWrappedKey } from './routes/wrapped-key.js';
import { handleRotateStart, handleRotateConfirm } from './routes/rotation.js';
import { handleGetAuditLog } from './routes/audit.js';
import { handleRevokeAll } from './routes/revocation.js';
import {
  handleCreateLinkCodeFull,
  handleLinkConfirm,
  handleGetLinkCodeStatus,
  handleListDevices,
  handleDeleteDevice,
} from './routes/devices.js';
import {
  handleCreateInvite,
  handleListInvites,
  handleAcceptInvite,
  handleDeclineInvite,
} from './routes/invites.js';
import { handleListAvailableProjects } from './routes/projects.js';
import { handleGetNotifications, handleDismissNotification } from './routes/notifications.js';

interface LambdaFunctionURLEvent {
  requestContext: {
    http: { method: string; path: string; sourceIp?: string };
    requestId: string;
  };
  headers: Record<string, string>;
  queryStringParameters?: Record<string, string>;
  body?: string;
  isBase64Encoded: boolean;
}

interface LambdaFunctionURLResult {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  isBase64Encoded?: boolean;
}

const TABLE_NAME = process.env['TABLE_NAME'] ?? '';
const SIGNUPS_ENABLED_PARAM = process.env['SIGNUPS_ENABLED_PARAM'] ?? '';

const client = new DynamoDBClient({});
const ddb = DynamoDBDocumentClient.from(client, {
  marshallOptions: { removeUndefinedValues: true },
});

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': 'none',
  'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function response(
  statusCode: number,
  body: string,
  headers: Record<string, string> = {},
  isBase64Encoded = false,
): LambdaFunctionURLResult {
  return {
    statusCode,
    headers: { ...CORS_HEADERS, ...headers },
    body,
    isBase64Encoded,
  };
}

export const handler = async (event: LambdaFunctionURLEvent): Promise<LambdaFunctionURLResult> => {
  const startTime = Date.now();
  const method = event.requestContext.http.method;
  const path = event.requestContext.http.path;
  const requestId = event.requestContext.requestId;

  logger.info('Request received', { requestId, operation: `${method} ${path}` });

  try {
    // OPTIONS (CORS preflight)
    if (method === 'OPTIONS') {
      return response(204, '', {});
    }

    // Health check — no auth
    if (method === 'GET' && path === '/health') {
      const result = handleHealth();
      return response(result.statusCode, result.body, result.headers);
    }

    // Registration challenge — no auth, IP rate limited
    if (method === 'GET' && path === '/v1/register/challenge') {
      const sourceIp = event.headers['x-forwarded-for']?.split(',')[0]?.trim()
        ?? event.requestContext.http.sourceIp
        ?? 'unknown';
      const rateCheck = await checkIpRateLimit(sourceIp, 'CHALLENGE', ddb, TABLE_NAME);
      if (!rateCheck.allowed) {
        return response(429, JSON.stringify({ error: 'rate_limited', message: 'Too many requests' }), {
          'Content-Type': 'application/json',
          ...rateLimitHeaders(rateCheck),
        });
      }
      const result = await handleChallenge(ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Link confirm — no auth, IP rate limited (new device submits its public key)
    if (method === 'POST' && path === '/v1/link-confirm') {
      const sourceIp = event.headers['x-forwarded-for']?.split(',')[0]?.trim()
        ?? event.requestContext.http.sourceIp
        ?? 'unknown';
      const rateCheck = await checkIpRateLimit(sourceIp, 'LINK_CONFIRM', ddb, TABLE_NAME);
      if (!rateCheck.allowed) {
        return response(429, JSON.stringify({ error: 'rate_limited', message: 'Too many requests' }), {
          'Content-Type': 'application/json',
          ...rateLimitHeaders(rateCheck),
        });
      }
      const result = await handleLinkConfirm(event.body, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Register — no auth, IP rate limited (1 req/sec; stricter for GitHub registrations)
    if (method === 'POST' && path === '/v1/auth/register') {
      const sourceIp = event.headers['x-forwarded-for']?.split(',')[0]?.trim()
        ?? event.requestContext.http.sourceIp
        ?? 'unknown';
      const rateCheck = await checkIpRateLimit(sourceIp, 'REGISTER', ddb, TABLE_NAME);
      if (!rateCheck.allowed) {
        return response(429, JSON.stringify({ error: 'rate_limited', message: 'Too many requests' }), {
          'Content-Type': 'application/json',
          ...rateLimitHeaders(rateCheck),
        });
      }
      // Stricter rate limit for registrations that include a GitHub username
      try {
        const parsed = event.body ? JSON.parse(event.body) : {};
        if (parsed.github) {
          const ghRateCheck = await checkIpRateLimit(sourceIp, 'REGISTER_GITHUB', ddb, TABLE_NAME);
          if (!ghRateCheck.allowed) {
            return response(429, JSON.stringify({ error: 'rate_limited', message: 'Too many requests' }), {
              'Content-Type': 'application/json',
              ...rateLimitHeaders(ghRateCheck),
            });
          }
        }
      } catch {
        // Invalid JSON — handleRegister will return 400
      }
      const result = await handleRegister(event.body, ddb, TABLE_NAME, SIGNUPS_ENABLED_PARAM, event.headers);
      return response(result.statusCode, result.body, result.headers);
    }

    // All other routes require authentication
    const auth = await authenticateRequest(event, ddb, TABLE_NAME);
    const tenantId = auth.tenantId;

    // Revoke all devices (emergency)
    if (path === '/v1/revoke-all' && method === 'POST') {
      const result = await handleRevokeAll(tenantId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Audit log
    if (path === '/v1/audit' && method === 'GET') {
      const result = await handleGetAuditLog(tenantId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Key rotation routes
    if (path === '/v1/rotate-start' && method === 'POST') {
      const result = await handleRotateStart(tenantId, auth.fingerprint, event.body, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    if (path === '/v1/rotate-confirm' && method === 'POST') {
      const result = await handleRotateConfirm(tenantId, auth.fingerprint, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Device linking routes (authenticated)
    if (path === '/v1/link-code' && method === 'POST') {
      const result = await handleCreateLinkCodeFull(tenantId, event.body, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    const linkStatusMatch = path.match(/^\/v1\/link-code\/([^/]+)\/status$/);
    if (linkStatusMatch && method === 'GET') {
      const codeHash = linkStatusMatch[1];
      const result = await handleGetLinkCodeStatus(tenantId, codeHash, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Device management routes (authenticated)
    if (path === '/v1/devices' && method === 'GET') {
      const result = await handleListDevices(tenantId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    const deviceDeleteMatch = path.match(/^\/v1\/devices\/(.+)$/);
    if (deviceDeleteMatch && method === 'DELETE') {
      const fingerprint = decodeURIComponent(deviceDeleteMatch[1]);
      const result = await handleDeleteDevice(tenantId, fingerprint, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Wrapped key routes
    if (path === '/v1/wrapped-key' && method === 'PUT') {
      const result = await handlePutWrappedKey(
        tenantId,
        auth.fingerprint,
        event.body,
        event.isBase64Encoded,
        ddb,
        TABLE_NAME,
      );
      return response(result.statusCode, result.body, result.headers);
    }

    if (path === '/v1/wrapped-key' && method === 'GET') {
      const result = await handleGetWrappedKey(tenantId, auth.fingerprint, ddb, TABLE_NAME);
      if (result.statusCode === 200 && result.headers['Content-Type'] === 'application/octet-stream') {
        return response(result.statusCode, result.body, result.headers, true);
      }
      return response(result.statusCode, result.body, result.headers);
    }

    // Blob routes
    const blobMatch = path.match(/^\/v1\/blobs\/([^/]+)$/);
    const restoreMatch = path.match(/^\/v1\/blobs\/([^/]+)\/restore$/);

    if (restoreMatch && method === 'POST') {
      const blobId = restoreMatch[1];
      const result = await handleRestore(blobId, tenantId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    if (path === '/v1/blobs/count' && method === 'GET') {
      const result = await handleCountBlobs(tenantId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    if (blobMatch) {
      const blobId = blobMatch[1];

      if (method === 'PUT') {
        const contentType = event.headers['content-type'] || event.headers['Content-Type'] || '';
        const result = await handlePutBlob(
          blobId,
          tenantId,
          event.body,
          event.isBase64Encoded,
          contentType,
          ddb,
          TABLE_NAME,
        );
        if (result.statusCode === 200 && result.headers['Content-Type'] === 'application/octet-stream') {
          return response(result.statusCode, result.body, result.headers, true);
        }
        return response(result.statusCode, result.body, result.headers);
      }

      if (method === 'GET') {
        const result = await handleGetBlob(blobId, tenantId, ddb, TABLE_NAME);
        if (result.statusCode === 200 && result.headers['Content-Type'] === 'application/octet-stream') {
          return response(result.statusCode, result.body, result.headers, true);
        }
        return response(result.statusCode, result.body, result.headers);
      }

      if (method === 'DELETE') {
        const result = await handleDeleteBlob(blobId, tenantId, ddb, TABLE_NAME);
        return response(result.statusCode, result.body, result.headers);
      }
    }

    if (path === '/v1/blobs' && method === 'GET') {
      const since = event.queryStringParameters?.['since'];
      const result = await handleListBlobs(tenantId, since, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Tenant routes
    const tenantDeleteMatch = path.match(/^\/v1\/tenants\/([^/]+)$/);

    if (path === '/v1/tenants' && method === 'POST') {
      const result = await handleCreateTenant(event.body, tenantId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    if (path === '/v1/tenants' && method === 'GET') {
      const result = await handleListTenants(tenantId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    if (tenantDeleteMatch && method === 'DELETE') {
      const projectTenantId = tenantDeleteMatch[1];
      const result = await handleDeleteTenant(projectTenantId, tenantId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Invite routes
    const inviteActionMatch = path.match(/^\/v1\/invites\/([^/]+)\/(accept|decline)$/);

    if (path === '/v1/invites' && method === 'POST') {
      const result = await handleCreateInvite(tenantId, auth.fingerprint, event.body, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    if (path === '/v1/invites' && method === 'GET') {
      const result = await handleListInvites(tenantId, auth.fingerprint, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    if (inviteActionMatch && method === 'POST') {
      const inviteId = inviteActionMatch[1];
      const action = inviteActionMatch[2];

      if (action === 'accept') {
        const result = await handleAcceptInvite(tenantId, auth.fingerprint, inviteId, ddb, TABLE_NAME);
        return response(result.statusCode, result.body, result.headers);
      }

      if (action === 'decline') {
        const result = await handleDeclineInvite(tenantId, auth.fingerprint, inviteId, event.body, ddb, TABLE_NAME);
        return response(result.statusCode, result.body, result.headers);
      }
    }

    // Notifications
    if (path === '/v1/notifications' && method === 'GET') {
      const result = await handleGetNotifications(tenantId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    const notificationDismissMatch = path.match(/^\/v1\/notifications\/(.+)\/dismiss$/);
    if (notificationDismissMatch && method === 'POST') {
      const notificationId = decodeURIComponent(notificationDismissMatch[1]);
      const result = await handleDismissNotification(tenantId, notificationId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Shared projects
    if (path === '/v1/projects/available' && method === 'GET') {
      const result = await handleListAvailableProjects(tenantId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Export
    if (path === '/v1/export' && method === 'GET') {
      const result = await handleExport(tenantId, ddb, TABLE_NAME);
      return response(result.statusCode, result.body, result.headers);
    }

    // Not found
    return response(404, JSON.stringify({ error: 'not_found', message: `No route for ${method} ${path}` }), {
      'Content-Type': 'application/json',
    });
  } catch (err: unknown) {
    const durationMs = Date.now() - startTime;

    if (err instanceof AuthError) {
      logger.warn('Auth failed', { requestId, durationMs, error: err.message });
      return response(err.statusCode, JSON.stringify({ error: 'auth_error', message: err.message }), {
        'Content-Type': 'application/json',
      });
    }

    logger.error('Unhandled error', { requestId, durationMs, error: String(err) });
    return response(500, JSON.stringify({ error: 'internal_error', message: 'Internal server error' }), {
      'Content-Type': 'application/json',
    });
  }
};
