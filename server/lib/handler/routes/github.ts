import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { logger } from '../logger.js';

interface HandlerResponse {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
}

const JSON_HEADERS = { 'Content-Type': 'application/json' };

// In-memory cache for GitHub keys (5 min TTL)
interface CacheEntry {
  keys: string[];
  expiresAt: number;
}
const githubKeyCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * Fetch SSH public keys from GitHub for a username.
 * Returns one key per line. Uses a 5-minute in-memory cache.
 */
export async function fetchGitHubKeys(username: string): Promise<string[]> {
  const now = Date.now();
  const cached = githubKeyCache.get(username);
  if (cached && now < cached.expiresAt) {
    return cached.keys;
  }

  const response = await fetch(
    `https://github.com/${encodeURIComponent(username)}.keys`,
    { signal: AbortSignal.timeout(10_000) },
  );

  if (response.status === 404) {
    throw new GitHubVerificationError('github_user_not_found', `GitHub user "${username}" not found`);
  }

  if (!response.ok) {
    throw new GitHubVerificationError('github_unreachable', `GitHub returned status ${response.status}`);
  }

  const text = await response.text();
  const keys = text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  githubKeyCache.set(username, { keys, expiresAt: now + CACHE_TTL_MS });
  return keys;
}

/**
 * Verify that a public key (in SSH authorized_keys format or base64) appears
 * on a GitHub account.
 */
export async function verifyKeyOnGitHub(
  publicKeyBase64: string,
  githubUsername: string,
): Promise<boolean> {
  const githubKeys = await fetchGitHubKeys(githubUsername);

  for (const ghKey of githubKeys) {
    const parts = ghKey.split(/\s+/);
    if (parts.length >= 2 && parts[1] === publicKeyBase64) {
      return true;
    }
    // Also match if the full key blob matches
    if (ghKey === publicKeyBase64) {
      return true;
    }
  }

  return false;
}

export class GitHubVerificationError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'GitHubVerificationError';
  }
}

/**
 * Store the GitHub username association on a tenant.
 * DynamoDB: PK: TENANT#{tenantId}, SK: GITHUB#{username}
 */
export async function storeGitHubAssociation(
  tenantId: string,
  githubUsername: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<void> {
  const now = new Date().toISOString();
  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `TENANT#${tenantId}`,
        SK: `GITHUB#${githubUsername}`,
        githubUsername,
        createdAt: now,
      },
    }),
  );
  logger.info('GitHub association stored', { tenantId, githubUsername });
}

/**
 * Look up if a tenant is associated with a GitHub username.
 * Returns the tenant ID if found, null otherwise.
 */
export async function findTenantByGitHub(
  githubUsername: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<string | null> {
  // We need a reverse lookup: GITHUB#{username} -> tenantId
  // Store a top-level record for this
  const result = await ddb.send(
    new GetCommand({
      TableName: tableName,
      Key: {
        PK: `GITHUB#${githubUsername}`,
        SK: 'META',
      },
    }),
  );

  return result.Item?.['tenantId'] ?? null;
}

/**
 * Store a reverse lookup record: GITHUB#{username} -> tenantId
 */
export async function storeGitHubReverseLookup(
  githubUsername: string,
  tenantId: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<void> {
  await ddb.send(
    new PutCommand({
      TableName: tableName,
      Item: {
        PK: `GITHUB#${githubUsername}`,
        SK: 'META',
        tenantId,
        createdAt: new Date().toISOString(),
      },
    }),
  );
}

// Export for testing
export function _resetGitHubKeyCache(): void {
  githubKeyCache.clear();
}
