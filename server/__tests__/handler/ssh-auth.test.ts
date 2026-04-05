import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as crypto from 'crypto';

const { mockSend } = vi.hoisted(() => ({ mockSend: vi.fn() }));

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({ send: mockSend }),
  },
  QueryCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  UpdateCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn().mockImplementation(function () {}),
}));

import {
  parseAuthHeaders,
  verifyTimestamp,
  buildCanonicalString,
  fingerprintFromPublicKey,
  verifySSHSignature,
  checkSequence,
  authenticateRequest,
  AuthError,
} from '../../lib/handler/middleware/ssh-auth.js';

const TABLE_NAME = 'chaoskb-test';
const ddb = { send: mockSend } as any;

// Generate a real Ed25519 key pair for tests
const { publicKey: ed25519PublicKey, privateKey: ed25519PrivateKey } = crypto.generateKeyPairSync('ed25519');
const rawPublicKeyBytes = ed25519PublicKey.export({ type: 'spki', format: 'der' }).subarray(12);
// Encode as SSH wire format: string "ssh-ed25519" + string <32-byte key>
function sshString(data: Buffer): Buffer {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  return Buffer.concat([len, data]);
}
const sshPublicKeyBlob = Buffer.concat([
  sshString(Buffer.from('ssh-ed25519')),
  sshString(rawPublicKeyBytes),
]);
const VALID_PUBLIC_KEY = sshPublicKeyBlob.toString('base64');

function signCanonical(canonical: string): string {
  return crypto.sign(null, Buffer.from(canonical), ed25519PrivateKey).toString('base64');
}

describe('parseAuthHeaders', () => {
  it('should parse new SSH-Signature format', () => {
    const headers = {
      authorization: 'SSH-Signature c2lnbmF0dXJl',
      'x-chaoskb-timestamp': '2026-03-20T10:00:00Z',
      'x-chaoskb-sequence': '42',
    };
    const result = parseAuthHeaders(headers);

    expect(result.signature).toBe('c2lnbmF0dXJl');
    expect(result.timestamp).toBe('2026-03-20T10:00:00Z');
    expect(result.sequence).toBe(42);
  });

  it('should parse legacy ChaosKB-SSH format', () => {
    const headers = {
      authorization: 'ChaosKB-SSH pubkey=dGVzdA==, ts=2026-03-20T10:00:00Z, sig=c2lnbmF0dXJl',
      'x-chaoskb-sequence': '5',
    };
    const result = parseAuthHeaders(headers);

    expect(result.signature).toBe('c2lnbmF0dXJl');
    expect(result.timestamp).toBe('2026-03-20T10:00:00Z');
    expect(result.sequence).toBe(5);
  });

  it('should reject invalid authorization scheme', () => {
    const headers = { authorization: 'Bearer token123' };
    expect(() => parseAuthHeaders(headers)).toThrow(AuthError);
    expect(() => parseAuthHeaders(headers)).toThrow('Invalid authorization scheme');
  });

  it('should reject missing authorization header', () => {
    expect(() => parseAuthHeaders({})).toThrow(AuthError);
    expect(() => parseAuthHeaders({})).toThrow('Missing Authorization header');
  });

  it('should default sequence to 0 if not provided', () => {
    const headers = {
      authorization: 'SSH-Signature c2lnbmF0dXJl',
      'x-chaoskb-timestamp': '2026-03-20T10:00:00Z',
    };
    const result = parseAuthHeaders(headers);
    expect(result.sequence).toBe(0);
  });

  it('should reject missing timestamp in new format', () => {
    const headers = {
      authorization: 'SSH-Signature c2lnbmF0dXJl',
    };
    expect(() => parseAuthHeaders(headers)).toThrow(AuthError);
    expect(() => parseAuthHeaders(headers)).toThrow('Missing required headers');
  });

  it('should reject invalid sequence number', () => {
    const headers = {
      authorization: 'SSH-Signature c2lnbmF0dXJl',
      'x-chaoskb-timestamp': '2026-03-20T10:00:00Z',
      'x-chaoskb-sequence': 'not-a-number',
    };
    expect(() => parseAuthHeaders(headers)).toThrow(AuthError);
    expect(() => parseAuthHeaders(headers)).toThrow('Invalid sequence number');
  });

  it('should reject legacy format with missing fields', () => {
    const headers = {
      authorization: 'ChaosKB-SSH pubkey=dGVzdA==',
    };
    expect(() => parseAuthHeaders(headers)).toThrow(AuthError);
    expect(() => parseAuthHeaders(headers)).toThrow('Missing required authorization fields');
  });
});

describe('verifyTimestamp', () => {
  it('should accept timestamp within 30 seconds', () => {
    const now = new Date().toISOString();
    expect(() => verifyTimestamp(now)).not.toThrow();
  });

  it('should reject timestamp older than 30 seconds', () => {
    const old = new Date(Date.now() - 60 * 1000).toISOString();
    expect(() => verifyTimestamp(old)).toThrow(AuthError);
    expect(() => verifyTimestamp(old)).toThrow('Request timestamp expired');
  });

  it('should reject future timestamp beyond 30 seconds', () => {
    const future = new Date(Date.now() + 60 * 1000).toISOString();
    expect(() => verifyTimestamp(future)).toThrow(AuthError);
  });

  it('should reject invalid timestamp format', () => {
    expect(() => verifyTimestamp('not-a-date')).toThrow(AuthError);
    expect(() => verifyTimestamp('not-a-date')).toThrow('Invalid timestamp format');
  });
});

describe('buildCanonicalString', () => {
  it('should build canonical string with body and sequence', () => {
    const result = buildCanonicalString('PUT', '/v1/blobs/b_123', '2026-03-20T10:00:00Z', 42, '{"v":1}');
    const lines = result.split('\n');

    expect(lines[0]).toBe('chaoskb-auth');
    expect(lines[1]).toBe('PUT /v1/blobs/b_123');
    expect(lines[2]).toBe('2026-03-20T10:00:00Z');
    expect(lines[3]).toBe('42');
    expect(lines[4]).toHaveLength(64); // SHA-256 hex digest
  });

  it('should build canonical string without body', () => {
    const result = buildCanonicalString('GET', '/v1/blobs', '2026-03-20T10:00:00Z', 1, null);
    const lines = result.split('\n');

    expect(lines[0]).toBe('chaoskb-auth');
    expect(lines[1]).toBe('GET /v1/blobs');
    expect(lines[2]).toBe('2026-03-20T10:00:00Z');
    expect(lines[3]).toBe('1');
    expect(lines[4]).toBe('');
  });

  it('should produce different output for different sequences', () => {
    const a = buildCanonicalString('GET', '/v1/blobs', '2026-03-20T10:00:00Z', 1, null);
    const b = buildCanonicalString('GET', '/v1/blobs', '2026-03-20T10:00:00Z', 2, null);
    expect(a).not.toBe(b);
  });
});

describe('fingerprintFromPublicKey', () => {
  it('should compute a consistent fingerprint', () => {
    const fp1 = fingerprintFromPublicKey('dGVzdA==');
    const fp2 = fingerprintFromPublicKey('dGVzdA==');
    expect(fp1).toBe(fp2);
  });

  it('should produce different fingerprints for different keys', () => {
    const fp1 = fingerprintFromPublicKey('dGVzdA==');
    const fp2 = fingerprintFromPublicKey('b3RoZXI=');
    expect(fp1).not.toBe(fp2);
  });
});

describe('verifySSHSignature', () => {
  it('should return true for valid signature', () => {
    const data = 'test-canonical-string';
    const sig = signCanonical(data);
    expect(verifySSHSignature(VALID_PUBLIC_KEY, data, sig)).toBe(true);
  });

  it('should return false for invalid signature', () => {
    const data = 'test-canonical-string';
    const badSig = crypto.randomBytes(64).toString('base64');
    expect(verifySSHSignature(VALID_PUBLIC_KEY, data, badSig)).toBe(false);
  });

  it('should return false for dummy key (timing equalization)', () => {
    const dummyKey = Buffer.alloc(32, 0x01).toString('base64');
    expect(verifySSHSignature(dummyKey, 'dummy', 'dummy')).toBe(false);
  });

  it('should return false for corrupted key data', () => {
    expect(verifySSHSignature('not-valid-base64!!!', 'data', 'sig')).toBe(false);
  });
});

describe('checkSequence', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should accept a new sequence number', async () => {
    mockSend.mockResolvedValueOnce({}); // conditional update succeeds

    await expect(
      checkSequence(ddb, TABLE_NAME, 'tenant-1', 'fp-1', 5),
    ).resolves.toBeUndefined();
  });

  it('should reject sequence number 0 or negative', async () => {
    await expect(
      checkSequence(ddb, TABLE_NAME, 'tenant-1', 'fp-1', 0),
    ).rejects.toThrow(AuthError);

    await expect(
      checkSequence(ddb, TABLE_NAME, 'tenant-1', 'fp-1', -1),
    ).rejects.toThrow('Sequence number must be positive');
  });

  it('should reject replayed sequence number', async () => {
    const condError = new Error('Condition not met');
    condError.name = 'ConditionalCheckFailedException';
    mockSend.mockRejectedValueOnce(condError);

    await expect(
      checkSequence(ddb, TABLE_NAME, 'tenant-1', 'fp-1', 3),
    ).rejects.toThrow('Replay detected');
  });

  it('should propagate non-conditional DynamoDB errors', async () => {
    mockSend.mockRejectedValueOnce(new Error('DynamoDB timeout'));

    await expect(
      checkSequence(ddb, TABLE_NAME, 'tenant-1', 'fp-1', 5),
    ).rejects.toThrow('DynamoDB timeout');
  });
});

describe('authenticateRequest', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  function makeEvent(overrides: {
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    body?: string | null;
  } = {}) {
    const timestamp = new Date().toISOString();
    const sequence = 1;
    const method = overrides.method ?? 'GET';
    const path = overrides.path ?? '/v1/blobs';
    const canonical = buildCanonicalString(method, path, timestamp, sequence, overrides.body ?? null);
    const sig = signCanonical(canonical);

    return {
      requestContext: { http: { method, path } },
      headers: {
        authorization: `SSH-Signature ${sig}`,
        'x-chaoskb-timestamp': timestamp,
        'x-chaoskb-sequence': String(sequence),
        'x-chaoskb-publickey': VALID_PUBLIC_KEY,
        ...overrides.headers,
      },
      body: overrides.body ?? null,
    };
  }

  it('should authenticate a valid request', async () => {
    // QueryCommand: tenant lookup returns matching key
    mockSend.mockResolvedValueOnce({
      Items: [{
        PK: `TENANT#test`,
        SK: 'META',
        publicKey: VALID_PUBLIC_KEY,
      }],
    });
    // UpdateCommand: sequence check succeeds
    mockSend.mockResolvedValueOnce({});

    const event = makeEvent();
    const result = await authenticateRequest(event, ddb, TABLE_NAME);

    expect(result.tenantId).toBeDefined();
    expect(result.publicKey).toBe(VALID_PUBLIC_KEY);
    expect(result.fingerprint).toBeDefined();
  });

  it('should reject when tenant not found (with timing equalization)', async () => {
    // QueryCommand: no tenant META
    mockSend.mockResolvedValueOnce({ Items: [] });
    // QueryCommand: no KEY_ALIAS record either
    mockSend.mockResolvedValueOnce({ Items: [] });

    const event = makeEvent();
    await expect(authenticateRequest(event, ddb, TABLE_NAME)).rejects.toThrow('Unknown public key');
  });

  it('should reject when public key does not match stored key', async () => {
    const otherKey = crypto.generateKeyPairSync('ed25519');
    const otherPubBuf = otherKey.publicKey.export({ type: 'spki', format: 'der' }).subarray(12);

    // QueryCommand: tenant has a different public key
    mockSend.mockResolvedValueOnce({
      Items: [{
        PK: 'TENANT#test',
        SK: 'META',
        publicKey: otherPubBuf.toString('base64'),
      }],
    });

    const event = makeEvent();
    await expect(authenticateRequest(event, ddb, TABLE_NAME)).rejects.toThrow('Public key mismatch');
  });

  it('should reject when signature is invalid', async () => {
    // QueryCommand: tenant lookup matches
    mockSend.mockResolvedValueOnce({
      Items: [{
        PK: 'TENANT#test',
        SK: 'META',
        publicKey: VALID_PUBLIC_KEY,
      }],
    });

    const event = makeEvent();
    // Corrupt the signature
    event.headers.authorization = `SSH-Signature ${crypto.randomBytes(64).toString('base64')}`;

    await expect(authenticateRequest(event, ddb, TABLE_NAME)).rejects.toThrow('Invalid signature');
  });

  it('should reject when timestamp is expired', async () => {
    const event = makeEvent();
    event.headers['x-chaoskb-timestamp'] = new Date(Date.now() - 60000).toISOString();

    await expect(authenticateRequest(event, ddb, TABLE_NAME)).rejects.toThrow('Request timestamp expired');
  });

  it('should reject when public key header is missing', async () => {
    const event = makeEvent();
    delete event.headers['x-chaoskb-publickey'];

    await expect(authenticateRequest(event, ddb, TABLE_NAME)).rejects.toThrow('Missing public key');
  });

  it('should skip sequence check when sequence is 0', async () => {
    // QueryCommand: tenant lookup
    mockSend.mockResolvedValueOnce({
      Items: [{
        PK: 'TENANT#test',
        SK: 'META',
        publicKey: VALID_PUBLIC_KEY,
      }],
    });
    // No sequence check call expected

    const timestamp = new Date().toISOString();
    const canonical = buildCanonicalString('GET', '/v1/blobs', timestamp, 0, null);
    const sig = signCanonical(canonical);

    const event = {
      requestContext: { http: { method: 'GET', path: '/v1/blobs' } },
      headers: {
        authorization: `SSH-Signature ${sig}`,
        'x-chaoskb-timestamp': timestamp,
        'x-chaoskb-sequence': '0',
        'x-chaoskb-publickey': VALID_PUBLIC_KEY,
      },
      body: null,
    };

    const result = await authenticateRequest(event, ddb, TABLE_NAME);
    expect(result.tenantId).toBeDefined();
    // Only 1 DDB call (tenant lookup), no sequence check
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('should authenticate with legacy ChaosKB-SSH header', async () => {
    const timestamp = new Date().toISOString();
    const sequence = 1;
    const canonical = buildCanonicalString('GET', '/v1/blobs', timestamp, sequence, null);
    const sig = signCanonical(canonical);

    // QueryCommand: tenant lookup
    mockSend.mockResolvedValueOnce({
      Items: [{
        PK: 'TENANT#test',
        SK: 'META',
        publicKey: VALID_PUBLIC_KEY,
      }],
    });
    // UpdateCommand: sequence check
    mockSend.mockResolvedValueOnce({});

    const event = {
      requestContext: { http: { method: 'GET', path: '/v1/blobs' } },
      headers: {
        authorization: `ChaosKB-SSH pubkey=${VALID_PUBLIC_KEY}, ts=${timestamp}, sig=${sig}`,
        'x-chaoskb-sequence': String(sequence),
      },
      body: null,
    };

    const result = await authenticateRequest(event, ddb, TABLE_NAME);
    expect(result.publicKey).toBe(VALID_PUBLIC_KEY);
  });

  it('should authenticate request with body', async () => {
    const body = '{"data": "test"}';

    // QueryCommand: tenant lookup
    mockSend.mockResolvedValueOnce({
      Items: [{
        PK: 'TENANT#test',
        SK: 'META',
        publicKey: VALID_PUBLIC_KEY,
      }],
    });
    // UpdateCommand: sequence check
    mockSend.mockResolvedValueOnce({});

    const event = makeEvent({ method: 'PUT', path: '/v1/blobs/b_1', body });
    const result = await authenticateRequest(event, ddb, TABLE_NAME);
    expect(result.tenantId).toBeDefined();
  });
});
