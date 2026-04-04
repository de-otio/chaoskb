import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock DynamoDB
const mockSend = vi.hoisted(() => vi.fn());

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: { from: () => ({ send: mockSend }) },
  PutCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  GetCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  QueryCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  UpdateCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  DeleteCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  BatchWriteCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn().mockImplementation(function () {}),
}));

const TABLE = 'chaoskb-test';
const TENANT = 'test-tenant-abc';
const ddb = { send: mockSend } as any;

// --- Registration → Wrapped Key → Retrieval ---

import { handlePutWrappedKey, handleGetWrappedKey } from '../../lib/handler/routes/wrapped-key.js';

describe('Wrapped key lifecycle', () => {
  beforeEach(() => mockSend.mockReset());

  it('stores and retrieves a wrapped key blob', async () => {
    const blobData = Buffer.from('sealed-master-key-blob').toString('base64');

    // Store
    mockSend.mockResolvedValueOnce({});
    const putResult = await handlePutWrappedKey(TENANT, 'fp123', blobData, false, ddb, TABLE);
    expect(putResult.statusCode).toBe(200);

    // Retrieve
    mockSend.mockResolvedValueOnce({
      Item: { PK: `TENANT#${TENANT}`, SK: 'WRAPPED_KEY#fp123', data: blobData },
    });
    const getResult = await handleGetWrappedKey(TENANT, 'fp123', ddb, TABLE);
    expect(getResult.statusCode).toBe(200);
    expect(getResult.body).toBe(blobData);
  });

  it('returns 404 for missing wrapped key', async () => {
    mockSend.mockResolvedValueOnce({ Item: undefined });
    const result = await handleGetWrappedKey(TENANT, 'unknown', ddb, TABLE);
    expect(result.statusCode).toBe(404);
  });

  it('rejects oversized wrapped key', async () => {
    const oversized = Buffer.alloc(5000).toString('base64');
    const result = await handlePutWrappedKey(TENANT, 'fp123', oversized, false, ddb, TABLE);
    expect(result.statusCode).toBe(400);
    expect(result.body).toContain('too large');
  });
});

// --- Replay Protection ---

import { checkSequence } from '../../lib/handler/middleware/ssh-auth.js';

describe('Replay protection lifecycle', () => {
  beforeEach(() => mockSend.mockReset());

  it('accepts first sequence number', async () => {
    mockSend.mockResolvedValueOnce({}); // conditional write succeeds
    await expect(checkSequence(ddb, TABLE, TENANT, 'fp1', 1)).resolves.not.toThrow();
  });

  it('rejects replayed sequence number', async () => {
    const error = Object.assign(new Error('Condition not met'), { name: 'ConditionalCheckFailedException' });
    mockSend.mockRejectedValueOnce(error);

    await expect(checkSequence(ddb, TABLE, TENANT, 'fp1', 1)).rejects.toThrow('Replay detected');
  });

  it('accepts higher sequence after lower', async () => {
    mockSend.mockResolvedValueOnce({}); // seq=1 accepted
    mockSend.mockResolvedValueOnce({}); // seq=5 accepted (skipped 2-4, that's ok)

    await checkSequence(ddb, TABLE, TENANT, 'fp1', 1);
    await checkSequence(ddb, TABLE, TENANT, 'fp1', 5);

    expect(mockSend).toHaveBeenCalledTimes(2);
  });

  it('rejects sequence <= 0', async () => {
    await expect(checkSequence(ddb, TABLE, TENANT, 'fp1', 0)).rejects.toThrow('must be positive');
    await expect(checkSequence(ddb, TABLE, TENANT, 'fp1', -1)).rejects.toThrow('must be positive');
  });
});

// --- Rate Limiting ---

import { checkRateLimit, checkIpRateLimit } from '../../lib/handler/middleware/rate-limit.js';

describe('Rate limiting lifecycle', () => {
  beforeEach(() => mockSend.mockReset());

  it('allows requests under limit', async () => {
    mockSend.mockResolvedValueOnce({ Attributes: { count: 50 } });
    const result = await checkRateLimit(TENANT, 'GET', ddb, TABLE);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(950); // 1000 - 50
  });

  it('blocks requests over limit', async () => {
    mockSend.mockResolvedValueOnce({ Attributes: { count: 1001 } });
    const result = await checkRateLimit(TENANT, 'GET', ddb, TABLE);
    expect(result.allowed).toBe(false);
    expect(result.retryAfter).toBeGreaterThan(0);
  });

  it('IP rate limiting blocks rapid registration', async () => {
    mockSend.mockResolvedValueOnce({ Attributes: { count: 2 } });
    const result = await checkIpRateLimit('192.168.1.1', 'REGISTER', ddb, TABLE);
    expect(result.allowed).toBe(false);
  });
});

// --- Invite Lifecycle ---

import { handleCreateInvite, handleAcceptInvite, handleDeclineInvite } from '../../lib/handler/routes/invites.js';

describe('Invite lifecycle', () => {
  beforeEach(() => mockSend.mockReset());

  it('creates an invite with all required fields', async () => {
    // Rate limit checks (sender hour, sender day, recipient pending)
    mockSend.mockResolvedValueOnce({ Attributes: { count: 1 } }); // hour
    mockSend.mockResolvedValueOnce({ Attributes: { count: 1 } }); // day
    mockSend.mockResolvedValueOnce({ Items: [] }); // recipient pending count
    mockSend.mockResolvedValueOnce({}); // put invite
    mockSend.mockResolvedValueOnce({}); // audit log

    const body = JSON.stringify({
      recipientFingerprint: 'fp-recipient',
      projectTenantId: 'proj-tenant-1',
      encryptedPayload: Buffer.from('encrypted-data').toString('base64'),
      role: 'editor',
    });

    const result = await handleCreateInvite(TENANT, 'fp-sender', body, ddb, TABLE);
    expect(result.statusCode).toBe(201);
    const parsed = JSON.parse(result.body);
    expect(parsed.status).toBe('pending');
    expect(parsed.inviteId).toBeTruthy();
  });

  it('accepts an invite (idempotent)', async () => {
    const inviteId = 'inv-123';

    // First accept
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `INVITE#${inviteId}`, SK: 'META',
        status: 'pending', recipientFingerprint: 'fp-me',
        encryptedPayload: 'enc-data', projectTenantId: 'proj-1',
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      },
    });
    mockSend.mockResolvedValueOnce({}); // update status
    mockSend.mockResolvedValueOnce({}); // audit log

    const result1 = await handleAcceptInvite(TENANT, 'fp-me', inviteId, ddb, TABLE);
    expect(result1.statusCode).toBe(200);
    expect(JSON.parse(result1.body).status).toBe('accepted');

    // Second accept (idempotent)
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `INVITE#${inviteId}`, SK: 'META',
        status: 'accepted', recipientFingerprint: 'fp-me',
        encryptedPayload: 'enc-data', projectTenantId: 'proj-1',
      },
    });

    const result2 = await handleAcceptInvite(TENANT, 'fp-me', inviteId, ddb, TABLE);
    expect(result2.statusCode).toBe(200);
    expect(JSON.parse(result2.body).status).toBe('already_accepted');
  });

  it('declines with sender block', async () => {
    const inviteId = 'inv-456';

    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `INVITE#${inviteId}`, SK: 'META',
        status: 'pending', recipientFingerprint: 'fp-me',
        senderFingerprint: 'fp-bad',
      },
    });
    mockSend.mockResolvedValueOnce({}); // update status
    mockSend.mockResolvedValueOnce({}); // block record
    mockSend.mockResolvedValueOnce({}); // audit log

    const body = JSON.stringify({ block: true, senderFingerprint: 'fp-bad' });
    const result = await handleDeclineInvite(TENANT, 'fp-me', inviteId, body, ddb, TABLE);
    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).status).toBe('declined');
  });
});

// --- Revocation ---

import { handleRevokeAll } from '../../lib/handler/routes/revocation.js';

describe('Revocation lifecycle', () => {
  beforeEach(() => mockSend.mockReset());

  it('deletes all KEY#, WRAPPED_KEY#, SEQUENCE#, ROTATION items', async () => {
    mockSend.mockResolvedValueOnce({
      Items: [
        { PK: `TENANT#${TENANT}`, SK: 'META' },
        { PK: `TENANT#${TENANT}`, SK: 'KEY#fp1' },
        { PK: `TENANT#${TENANT}`, SK: 'KEY#fp2' },
        { PK: `TENANT#${TENANT}`, SK: 'WRAPPED_KEY#fp1' },
        { PK: `TENANT#${TENANT}`, SK: 'WRAPPED_KEY#fp2' },
        { PK: `TENANT#${TENANT}`, SK: 'SEQUENCE#fp1' },
        { PK: `TENANT#${TENANT}`, SK: 'ROTATION' },
        { PK: `TENANT#${TENANT}`, SK: 'BLOB#b1' },
      ],
    });
    mockSend.mockResolvedValueOnce({}); // batch delete
    mockSend.mockResolvedValueOnce({}); // audit log

    const result = await handleRevokeAll(TENANT, ddb, TABLE);
    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).status).toBe('revoked');

    // Verify batch delete was called with correct items (not META or BLOB#)
    const batchCall = mockSend.mock.calls[1][0];
    const deletedSKs = batchCall.input.RequestItems[TABLE].map((r: any) => r.DeleteRequest.Key.SK);
    expect(deletedSKs).toContain('KEY#fp1');
    expect(deletedSKs).toContain('WRAPPED_KEY#fp2');
    expect(deletedSKs).toContain('SEQUENCE#fp1');
    expect(deletedSKs).toContain('ROTATION');
    expect(deletedSKs).not.toContain('META');
    expect(deletedSKs).not.toContain('BLOB#b1');
  });
});

// --- Audit Log ---

import { logAuditEvent, handleGetAuditLog } from '../../lib/handler/routes/audit.js';

describe('Audit log lifecycle', () => {
  beforeEach(() => mockSend.mockReset());

  it('logs event and retrieves it', async () => {
    // Log
    mockSend.mockResolvedValueOnce({});
    await logAuditEvent(ddb, TABLE, TENANT, {
      eventType: 'registered',
      fingerprint: 'fp1',
      metadata: { source: 'bootstrap' },
    });

    expect(mockSend).toHaveBeenCalledTimes(1);
    const putItem = mockSend.mock.calls[0][0].input.Item;
    expect(putItem.PK).toBe(`TENANT#${TENANT}`);
    expect(putItem.SK).toMatch(/^AUDIT#/);
    expect(putItem.eventType).toBe('registered');

    // Retrieve
    mockSend.mockResolvedValueOnce({
      Items: [putItem],
    });
    const result = await handleGetAuditLog(TENANT, ddb, TABLE);
    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.events).toHaveLength(1);
    expect(parsed.events[0].eventType).toBe('registered');
  });
});

// --- Rotation Lifecycle ---

import { handleRotateStart } from '../../lib/handler/routes/rotation.js';

describe('Rotation lifecycle', () => {
  beforeEach(() => mockSend.mockReset());

  it('starts rotation and stores state', async () => {
    // Check no existing rotation
    mockSend.mockResolvedValueOnce({ Item: undefined });
    // Get tenant META
    mockSend.mockResolvedValueOnce({ Item: { PK: `TENANT#${TENANT}`, SK: 'META', publicKey: 'old-pk' } });
    // Put rotation record
    mockSend.mockResolvedValueOnce({});
    // Update tenant META
    mockSend.mockResolvedValueOnce({});
    // Put new wrapped key
    mockSend.mockResolvedValueOnce({});

    const body = JSON.stringify({
      newPublicKey: Buffer.from('new-pk').toString('base64'),
      wrappedBlob: Buffer.from('wrapped').toString('base64'),
    });

    const result = await handleRotateStart(TENANT, 'fp-old', body, ddb, TABLE);
    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).status).toBe('rotation_started');
  });

  it('rejects rotation when one is already in progress', async () => {
    mockSend.mockResolvedValueOnce({
      Item: { PK: `TENANT#${TENANT}`, SK: 'ROTATION', phase: 'started' },
    });

    const body = JSON.stringify({
      newPublicKey: Buffer.from('pk').toString('base64'),
      wrappedBlob: Buffer.from('wk').toString('base64'),
    });

    const result = await handleRotateStart(TENANT, 'fp-old', body, ddb, TABLE);
    expect(result.statusCode).toBe(409);
  });
});
