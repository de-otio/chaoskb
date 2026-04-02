import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as crypto from 'crypto';

const { mockSend, mockSsmSend } = vi.hoisted(() => ({
  mockSend: vi.fn(),
  mockSsmSend: vi.fn(),
}));

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({ send: mockSend }),
  },
  PutCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  GetCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  DeleteCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn().mockImplementation(function () {}),
}));

vi.mock('@aws-sdk/client-ssm', () => ({
  SSMClient: vi.fn().mockImplementation(function (this: any) { this.send = mockSsmSend; }),
  GetParameterCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
}));

import { handleRegister, handleChallenge, _resetSignupsCache } from '../../lib/handler/routes/register.js';
import { _resetGitHubKeyCache } from '../../lib/handler/routes/github.js';

const TABLE_NAME = 'chaoskb-test';
const PARAM_NAME = '/chaoskb/test/signups-enabled';
const ddb = { send: mockSend } as any;

// Generate a real Ed25519 key pair for signature tests
const { publicKey: ed25519PublicKey, privateKey: ed25519PrivateKey } = crypto.generateKeyPairSync('ed25519');
const publicKeyBuffer = ed25519PublicKey.export({ type: 'spki', format: 'der' }).subarray(12); // strip DER prefix
const VALID_PUBLIC_KEY = publicKeyBuffer.toString('base64');

function signChallenge(nonce: string): string {
  const data = Buffer.from(`chaoskb-register\n${nonce}`);
  const signature = crypto.sign(null, data, ed25519PrivateKey);
  return signature.toString('base64');
}

const VALID_NONCE = crypto.randomBytes(32).toString('base64');

/** Helper: mock a successful atomic challenge consumption (DeleteCommand with ALL_OLD). */
function mockChallengeConsumed(nonce: string) {
  mockSend.mockResolvedValueOnce({
    Attributes: {
      PK: `CHALLENGE#${nonce}`,
      SK: 'META',
      expiresAt: new Date(Date.now() + 60000).toISOString(),
    },
  });
}

/** Helper: mock a challenge that was already consumed (ConditionalCheckFailedException). */
function mockChallengeAlreadyConsumed() {
  const err = new Error('Condition not met');
  err.name = 'ConditionalCheckFailedException';
  mockSend.mockRejectedValueOnce(err);
}

/** Helper: mock an expired challenge consumption. */
function mockChallengeExpired(nonce: string) {
  mockSend.mockResolvedValueOnce({
    Attributes: {
      PK: `CHALLENGE#${nonce}`,
      SK: 'META',
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    },
  });
}

describe('GET /v1/register/challenge', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should return a challenge nonce (200)', async () => {
    mockSend.mockResolvedValueOnce({}); // PutCommand succeeds

    const result = await handleChallenge(ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.challenge).toBeDefined();
    expect(typeof parsed.challenge).toBe('string');
    // 32 bytes base64 = 44 chars
    expect(Buffer.from(parsed.challenge, 'base64').length).toBe(32);
    expect(parsed.expiresAt).toBeDefined();
  });
});

describe('POST /v1/auth/register (challenge-response)', () => {
  beforeEach(() => {
    mockSend.mockReset();
    mockSsmSend.mockReset();
    _resetSignupsCache();
  });

  it('should register successfully with valid challenge signature (201)', async () => {
    const nonce = VALID_NONCE;
    const signature = signChallenge(nonce);

    // SSM returns signups enabled
    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: 'true' } });
    // DeleteCommand: atomic challenge consumption (returns old item)
    mockChallengeConsumed(nonce);
    // PutCommand: create tenant
    mockSend.mockResolvedValueOnce({});
    // PutCommand: audit event (called by logAuditEvent)
    mockSend.mockResolvedValueOnce({});

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(201);
    const parsed = JSON.parse(result.body);
    expect(parsed.tenantId).toBeDefined();
    expect(parsed.publicKey).toBe(VALID_PUBLIC_KEY);
  });

  it('should return 400 when signedChallenge is missing', async () => {
    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: 'true' } });

    const body = JSON.stringify({ publicKey: VALID_PUBLIC_KEY });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('invalid_request');
    expect(JSON.parse(result.body).message).toContain('signedChallenge');
  });

  it('should return 401 when signature is invalid', async () => {
    const nonce = VALID_NONCE;
    const invalidSignature = crypto.randomBytes(64).toString('base64');

    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: 'true' } });
    // DeleteCommand: atomic challenge consumption
    mockChallengeConsumed(nonce);

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: invalidSignature,
      challengeNonce: nonce,
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(401);
    expect(JSON.parse(result.body).error).toBe('invalid_signature');
  });

  it('should return 400 when challenge is expired', async () => {
    const nonce = VALID_NONCE;
    const signature = signChallenge(nonce);

    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: 'true' } });
    // DeleteCommand: atomic consumption returns expired item
    mockChallengeExpired(nonce);

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('challenge_expired');
  });

  it('should return 400 when challenge is reused (not found)', async () => {
    const nonce = VALID_NONCE;
    const signature = signChallenge(nonce);

    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: 'true' } });
    // DeleteCommand: ConditionalCheckFailedException (already consumed)
    mockChallengeAlreadyConsumed();

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('invalid_challenge');
  });

  it('should return 403 when signups disabled', async () => {
    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: 'false' } });

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: 'sig',
      challengeNonce: 'nonce',
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(403);
    expect(JSON.parse(result.body).error).toBe('signups_disabled');
  });

  it('should return 409 when already registered', async () => {
    const nonce = VALID_NONCE;
    const signature = signChallenge(nonce);

    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: 'true' } });
    // DeleteCommand: atomic challenge consumption
    mockChallengeConsumed(nonce);
    // PutCommand: conditional check fails (tenant already exists)
    const condError = new Error('Condition not met');
    condError.name = 'ConditionalCheckFailedException';
    mockSend.mockRejectedValueOnce(condError);

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(409);
    expect(JSON.parse(result.body).error).toBe('already_registered');
  });
});

describe('POST /v1/auth/register (GitHub integration)', () => {
  beforeEach(() => {
    mockSend.mockReset();
    mockSsmSend.mockReset();
    _resetSignupsCache();
    _resetGitHubKeyCache();
  });

  const originalFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  function setupValidRegistration(nonce: string) {
    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: 'true' } });
    mockChallengeConsumed(nonce);
  }

  it('should return uniform github_verification_failed when GitHub user not found', async () => {
    const nonce = VALID_NONCE;
    const signature = signChallenge(nonce);
    setupValidRegistration(nonce);

    // GitHub returns 404
    globalThis.fetch = vi.fn().mockResolvedValueOnce({ ok: false, status: 404 });

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
      github: 'nonexistent',
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('github_verification_failed');
  });

  it('should return uniform github_verification_failed when key not on GitHub', async () => {
    const nonce = VALID_NONCE;
    const signature = signChallenge(nonce);
    setupValidRegistration(nonce);

    // GitHub returns keys but none match
    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => 'ssh-ed25519 AAAAC3otherkey user@host\n',
    });

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
      github: 'someuser',
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('github_verification_failed');
  });

  it('should return uniform github_verification_failed when GitHub unreachable', async () => {
    const nonce = VALID_NONCE;
    const signature = signChallenge(nonce);
    setupValidRegistration(nonce);

    // GitHub returns 503
    globalThis.fetch = vi.fn().mockResolvedValueOnce({ ok: false, status: 503 });

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
      github: 'someuser',
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('github_verification_failed');
  });

  it('all GitHub failure modes return identical response structure', async () => {
    const responses: string[] = [];

    for (const fetchResponse of [
      { ok: false, status: 404 }, // user not found
      { ok: false, status: 503 }, // unreachable
    ]) {
      const nonce = crypto.randomBytes(32).toString('base64');
      const signature = signChallenge(nonce);
      mockSend.mockReset();
      mockSsmSend.mockReset();
      _resetSignupsCache();
      setupValidRegistration(nonce);

      globalThis.fetch = vi.fn().mockResolvedValueOnce(fetchResponse);

      const body = JSON.stringify({
        publicKey: VALID_PUBLIC_KEY,
        signedChallenge: signature,
        challengeNonce: nonce,
        github: 'testuser',
      });
      const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);
      responses.push(result.body);
    }

    // All responses should have identical structure
    const parsed = responses.map((r) => JSON.parse(r));
    expect(parsed[0].error).toBe(parsed[1].error);
    expect(parsed[0].error).toBe('github_verification_failed');
  });

  it('auto_linked response should not include tenantId', async () => {
    const nonce = VALID_NONCE;
    const signature = signChallenge(nonce);
    setupValidRegistration(nonce);

    const githubKeysResponse = {
      ok: true,
      status: 200,
      text: async () => `ssh-ed25519 ${VALID_PUBLIC_KEY} user@host\n`,
    };

    // GitHub returns matching key (initial verify + fresh-fetch)
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(githubKeysResponse)  // verifyKeyOnGitHub
      .mockResolvedValueOnce(githubKeysResponse);  // fetchGitHubKeysFresh

    // findTenantByGitHub: existing tenant found
    mockSend.mockResolvedValueOnce({
      Item: { PK: 'GITHUB#testuser', SK: 'META', tenantId: 'existing-tenant' },
    });
    // createNotification: PutCommand
    mockSend.mockResolvedValueOnce({});
    // logAuditEvent: PutCommand
    mockSend.mockResolvedValueOnce({});

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
      github: 'testuser',
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.status).toBe('auto_linked');
    expect(parsed.github).toBe('testuser');
    expect(parsed.tenantId).toBeUndefined(); // M1: no tenantId leak
  });

  it('should register with GitHub when no existing tenant (new registration)', async () => {
    const nonce = crypto.randomBytes(32).toString('base64');
    const signature = signChallenge(nonce);
    mockSend.mockReset();
    mockSsmSend.mockReset();
    _resetSignupsCache();

    setupValidRegistration(nonce);

    const githubKeysResponse = {
      ok: true,
      status: 200,
      text: async () => `ssh-ed25519 ${VALID_PUBLIC_KEY} user@host\n`,
    };
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(githubKeysResponse); // verifyKeyOnGitHub

    // findTenantByGitHub: no existing tenant
    mockSend.mockResolvedValueOnce({ Item: undefined });
    // PutCommand: create tenant
    mockSend.mockResolvedValueOnce({});
    // storeGitHubReverseLookup: PutCommand (conditional)
    mockSend.mockResolvedValueOnce({});
    // storeGitHubAssociation: PutCommand
    mockSend.mockResolvedValueOnce({});
    // logAuditEvent: PutCommand
    mockSend.mockResolvedValueOnce({});

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
      github: 'newuser',
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(201);
    const parsed = JSON.parse(result.body);
    expect(parsed.github).toBe('newuser');
  });

  it('should return github_verification_failed when username claimed by another tenant', async () => {
    const nonce = crypto.randomBytes(32).toString('base64');
    const signature = signChallenge(nonce);
    mockSend.mockReset();
    mockSsmSend.mockReset();
    _resetSignupsCache();

    setupValidRegistration(nonce);

    globalThis.fetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => `ssh-ed25519 ${VALID_PUBLIC_KEY} user@host\n`,
    });

    // findTenantByGitHub: no existing tenant
    mockSend.mockResolvedValueOnce({ Item: undefined });
    // PutCommand: create tenant
    mockSend.mockResolvedValueOnce({});
    // storeGitHubReverseLookup: ConditionalCheckFailedException (username claimed)
    const condError = new Error('Condition not met');
    condError.name = 'ConditionalCheckFailedException';
    mockSend.mockRejectedValueOnce(condError);

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
      github: 'claimed-user',
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('github_verification_failed');
  });

  it('should fall through to normal registration when GitHub unreachable during auto-link', async () => {
    const nonce = crypto.randomBytes(32).toString('base64');
    const signature = signChallenge(nonce);
    mockSend.mockReset();
    mockSsmSend.mockReset();
    _resetSignupsCache();

    setupValidRegistration(nonce);

    // Initial verifyKeyOnGitHub succeeds
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => `ssh-ed25519 ${VALID_PUBLIC_KEY} user@host\n`,
      })
      // fetchGitHubKeysFresh fails (GitHub unreachable)
      .mockRejectedValueOnce(new Error('network error'));

    // findTenantByGitHub: existing tenant found
    mockSend.mockResolvedValueOnce({
      Item: { PK: 'GITHUB#testuser', SK: 'META', tenantId: 'existing-tenant' },
    });
    // Falls through to normal registration since fresh keys unavailable
    // PutCommand: create tenant
    mockSend.mockResolvedValueOnce({});
    // logAuditEvent: PutCommand
    mockSend.mockResolvedValueOnce({});

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
      github: 'testuser',
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    // Should fall through to 201 (normal registration), not 200 (auto-linked)
    expect(result.statusCode).toBe(201);
  });

  it('should include deviceInfo in registration request', async () => {
    const nonce = VALID_NONCE;
    const signature = signChallenge(nonce);

    mockSsmSend.mockResolvedValueOnce({ Parameter: { Value: 'true' } });
    mockChallengeConsumed(nonce);
    // PutCommand: create tenant
    mockSend.mockResolvedValueOnce({});
    // logAuditEvent
    mockSend.mockResolvedValueOnce({});

    const body = JSON.stringify({
      publicKey: VALID_PUBLIC_KEY,
      signedChallenge: signature,
      challengeNonce: nonce,
      deviceInfo: {
        hostname: 'test-host',
        platform: 'darwin',
        arch: 'arm64',
      },
    });
    const result = await handleRegister(body, ddb, TABLE_NAME, PARAM_NAME);

    expect(result.statusCode).toBe(201);
  });
});

