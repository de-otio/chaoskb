import * as crypto from 'crypto';
import { DynamoDBDocumentClient, PutCommand, GetCommand } from '@aws-sdk/lib-dynamodb';
import { logger } from '../logger.js';


// In-memory cache for GitHub keys (5 min TTL)
interface CacheEntry {
  keys: string[];
  expiresAt: number;
}
const githubKeyCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 5 * 60 * 1000;

/** GitHub username constraints: 1-39 alphanumeric or hyphen, no leading/trailing hyphen, no consecutive hyphens. */
const GITHUB_USERNAME_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}$/;

export function isValidGitHubUsername(username: string): boolean {
  return GITHUB_USERNAME_RE.test(username);
}

/**
 * Fetch SSH public keys from GitHub for a username.
 * Returns one key per line. Uses a 5-minute in-memory cache.
 */
export async function fetchGitHubKeys(username: string): Promise<string[]> {
  if (!isValidGitHubUsername(username)) {
    throw new GitHubVerificationError('github_verification_failed', 'Could not verify key against GitHub account');
  }
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
    throw new GitHubVerificationError('github_verification_failed', 'Could not verify key against GitHub account');
  }

  if (!response.ok) {
    throw new GitHubVerificationError('github_verification_failed', 'Could not verify key against GitHub account');
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
 * Fetch SSH keys from GitHub, bypassing the in-memory cache.
 * Used at auto-link time to ensure we have the latest key list.
 */
export async function fetchGitHubKeysFresh(username: string): Promise<string[]> {
  githubKeyCache.delete(username);
  return fetchGitHubKeys(username);
}

/**
 * Check whether a public key (base64 blob) appears in a list of GitHub SSH key lines.
 */
export function keyAppearsInGitHubKeys(publicKeyBase64: string, githubKeys: string[]): boolean {
  const suppliedBuf = Buffer.from(publicKeyBase64);
  for (const ghKey of githubKeys) {
    const parts = ghKey.split(/\s+/);
    const candidate = parts.length >= 2 ? parts[1] : ghKey;
    const candidateBuf = Buffer.from(candidate);
    if (suppliedBuf.length === candidateBuf.length && crypto.timingSafeEqual(suppliedBuf, candidateBuf)) {
      return true;
    }
  }
  return false;
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
  return keyAppearsInGitHubKeys(publicKeyBase64, githubKeys);
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
 * Store a reverse lookup record: GITHUB#{username} -> tenantId.
 * Uses a conditional write to prevent a different tenant from claiming
 * a username that is already associated with another tenant.
 * Returns true if stored, false if already claimed by a different tenant.
 */
export async function storeGitHubReverseLookup(
  githubUsername: string,
  tenantId: string,
  ddb: DynamoDBDocumentClient,
  tableName: string,
): Promise<boolean> {
  try {
    await ddb.send(
      new PutCommand({
        TableName: tableName,
        Item: {
          PK: `GITHUB#${githubUsername}`,
          SK: 'META',
          tenantId,
          createdAt: new Date().toISOString(),
        },
        ConditionExpression: 'attribute_not_exists(PK) OR tenantId = :tid',
        ExpressionAttributeValues: {
          ':tid': tenantId,
        },
      }),
    );
    return true;
  } catch (err: unknown) {
    if ((err as { name?: string }).name === 'ConditionalCheckFailedException') {
      logger.warn('GitHub username already claimed by another tenant', { githubUsername });
      return false;
    }
    throw err;
  }
}

// Export for testing
export function _resetGitHubKeyCache(): void {
  githubKeyCache.clear();
}
