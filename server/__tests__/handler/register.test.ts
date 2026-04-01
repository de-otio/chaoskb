import { describe, it, expect, vi, beforeEach } from 'vitest';
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
    // GetCommand: challenge lookup succeeds
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `CHALLENGE#${nonce}`,
        SK: 'META',
        expiresAt: new Date(Date.now() + 60000).toISOString(),
      },
    });
    // DeleteCommand: consume challenge
    mockSend.mockResolvedValueOnce({});
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
    // Challenge lookup succeeds
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `CHALLENGE#${nonce}`,
        SK: 'META',
        expiresAt: new Date(Date.now() + 60000).toISOString(),
      },
    });
    // DeleteCommand: consume challenge
    mockSend.mockResolvedValueOnce({});

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
    // Challenge lookup: expired
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `CHALLENGE#${nonce}`,
        SK: 'META',
        expiresAt: new Date(Date.now() - 1000).toISOString(), // already expired
      },
    });
    // DeleteCommand: cleanup expired challenge
    mockSend.mockResolvedValueOnce({});

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
    // Challenge lookup: not found (already consumed)
    mockSend.mockResolvedValueOnce({ Item: undefined });

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
    // Challenge valid
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `CHALLENGE#${nonce}`,
        SK: 'META',
        expiresAt: new Date(Date.now() + 60000).toISOString(),
      },
    });
    // DeleteCommand: consume challenge
    mockSend.mockResolvedValueOnce({});
    // PutCommand: conditional check fails
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
