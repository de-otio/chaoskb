import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockSend } = vi.hoisted(() => ({ mockSend: vi.fn() }));

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({ send: mockSend }),
  },
  PutCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; this._type = 'PutCommand'; }),
  GetCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; this._type = 'GetCommand'; }),
  DeleteCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; this._type = 'DeleteCommand'; }),
  UpdateCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; this._type = 'UpdateCommand'; }),
  QueryCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; this._type = 'QueryCommand'; }),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn().mockImplementation(function () {}),
}));

import {
  handleCreateLinkCodeFull,
  handleLinkConfirm,
  handleGetLinkCodeStatus,
  handleListDevices,
  handleDeleteDevice,
} from '../../lib/handler/routes/devices.js';

import * as crypto from 'crypto';

const TABLE_NAME = 'chaoskb-test';
const TENANT_ID = 'test-tenant-abc';
const ddb = { send: mockSend } as any;

describe('POST /v1/link-code', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should create a link code (201)', async () => {
    // Two PutCommands: tenant-scoped LINK# and reverse-lookup LINK_CODE#
    mockSend.mockResolvedValueOnce({});
    mockSend.mockResolvedValueOnce({});

    const body = JSON.stringify({ codeHash: 'abc123hash' });
    const result = await handleCreateLinkCodeFull(TENANT_ID, body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(201);
    const parsed = JSON.parse(result.body);
    expect(parsed.status).toBe('created');
    expect(parsed.expiresAt).toBeDefined();
    expect(mockSend).toHaveBeenCalledTimes(2);
  });

  it('should return 400 for missing body', async () => {
    const result = await handleCreateLinkCodeFull(TENANT_ID, null, ddb, TABLE_NAME);
    expect(result.statusCode).toBe(400);
  });

  it('should return 400 for missing codeHash', async () => {
    const body = JSON.stringify({ foo: 'bar' });
    const result = await handleCreateLinkCodeFull(TENANT_ID, body, ddb, TABLE_NAME);
    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('invalid_request');
  });

  it('should return 400 for invalid JSON', async () => {
    const result = await handleCreateLinkCodeFull(TENANT_ID, '{bad json', ddb, TABLE_NAME);
    expect(result.statusCode).toBe(400);
  });
});

describe('POST /v1/link-confirm', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  const linkCode = 'A7kM9xQ2';
  const codeHash = crypto.createHash('sha256').update(linkCode).digest('hex');
  const newPublicKey = Buffer.from('b'.repeat(32)).toString('base64');

  it('should confirm a valid link code (200)', async () => {
    // GetCommand: reverse-lookup LINK_CODE#
    mockSend.mockResolvedValueOnce({
      Item: { PK: `LINK_CODE#${codeHash}`, SK: 'META', tenantId: TENANT_ID },
    });
    // GetCommand: tenant-scoped LINK#
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `TENANT#${TENANT_ID}`,
        SK: `LINK#${codeHash}`,
        newPublicKey: null,
        failureCount: 0,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
    });
    // UpdateCommand: store newPublicKey
    mockSend.mockResolvedValueOnce({});

    const body = JSON.stringify({ linkCode, publicKey: newPublicKey });
    const result = await handleLinkConfirm(body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).status).toBe('confirmed');
  });

  it('should return 404 for unknown link code', async () => {
    // Reverse-lookup returns nothing
    mockSend.mockResolvedValueOnce({ Item: undefined });

    const body = JSON.stringify({ linkCode: 'BADCODE1', publicKey: newPublicKey });
    const result = await handleLinkConfirm(body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(404);
    expect(JSON.parse(result.body).error).toBe('not_found');
  });

  it('should return 410 for expired link code', async () => {
    // Reverse-lookup
    mockSend.mockResolvedValueOnce({
      Item: { PK: `LINK_CODE#${codeHash}`, SK: 'META', tenantId: TENANT_ID },
    });
    // Tenant-scoped record with past expiry
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `TENANT#${TENANT_ID}`,
        SK: `LINK#${codeHash}`,
        newPublicKey: null,
        failureCount: 0,
        expiresAtISO: new Date(Date.now() - 60_000).toISOString(),
      },
    });

    const body = JSON.stringify({ linkCode, publicKey: newPublicKey });
    const result = await handleLinkConfirm(body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(410);
    expect(JSON.parse(result.body).error).toBe('expired');
  });

  it('should return 429 and delete record after 3 failures', async () => {
    // Reverse-lookup
    mockSend.mockResolvedValueOnce({
      Item: { PK: `LINK_CODE#${codeHash}`, SK: 'META', tenantId: TENANT_ID },
    });
    // Tenant-scoped record with failureCount >= 3
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `TENANT#${TENANT_ID}`,
        SK: `LINK#${codeHash}`,
        newPublicKey: null,
        failureCount: 3,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
    });
    // Two DeleteCommands (tenant-scoped + reverse-lookup)
    mockSend.mockResolvedValueOnce({});
    mockSend.mockResolvedValueOnce({});

    const body = JSON.stringify({ linkCode, publicKey: newPublicKey });
    const result = await handleLinkConfirm(body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(429);
    expect(JSON.parse(result.body).error).toBe('too_many_failures');
    expect(mockSend).toHaveBeenCalledTimes(4); // 2 gets + 2 deletes
  });

  it('should return 400 for missing body', async () => {
    const result = await handleLinkConfirm(null, ddb, TABLE_NAME);
    expect(result.statusCode).toBe(400);
  });

  it('should return 400 for missing fields', async () => {
    const body = JSON.stringify({ linkCode: 'ABC' });
    const result = await handleLinkConfirm(body, ddb, TABLE_NAME);
    expect(result.statusCode).toBe(400);
  });

  it('should return 400 for invalid JSON', async () => {
    const result = await handleLinkConfirm('{{bad', ddb, TABLE_NAME);
    expect(result.statusCode).toBe(400);
  });

  it('should return 404 when tenant-scoped link record not found', async () => {
    // Reverse-lookup succeeds
    mockSend.mockResolvedValueOnce({
      Item: { PK: `LINK_CODE#${codeHash}`, SK: 'META', tenantId: TENANT_ID },
    });
    // Tenant-scoped record missing
    mockSend.mockResolvedValueOnce({ Item: undefined });

    const body = JSON.stringify({ linkCode, publicKey: newPublicKey });
    const result = await handleLinkConfirm(body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(404);
  });

  it('should return 404 when update conditional check fails (link code consumed)', async () => {
    // Reverse-lookup
    mockSend.mockResolvedValueOnce({
      Item: { PK: `LINK_CODE#${codeHash}`, SK: 'META', tenantId: TENANT_ID },
    });
    // Tenant-scoped record
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `TENANT#${TENANT_ID}`,
        SK: `LINK#${codeHash}`,
        newPublicKey: null,
        failureCount: 0,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
    });
    // UpdateCommand: ConditionalCheckFailedException
    const condError = new Error('Condition not met');
    condError.name = 'ConditionalCheckFailedException';
    mockSend.mockRejectedValueOnce(condError);

    const body = JSON.stringify({ linkCode, publicKey: newPublicKey });
    const result = await handleLinkConfirm(body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(404);
    expect(JSON.parse(result.body).error).toBe('not_found');
  });
});

describe('GET /v1/link-code/{hash}/status', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should return waiting when no public key yet', async () => {
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `TENANT#${TENANT_ID}`,
        SK: 'LINK#somehash',
        newPublicKey: null,
        failureCount: 0,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
    });

    const result = await handleGetLinkCodeStatus(TENANT_ID, 'somehash', ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).status).toBe('waiting');
  });

  it('should return ready with public key', async () => {
    const pubKey = 'AAAAC3NzaC1lZDI1NTE5';
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `TENANT#${TENANT_ID}`,
        SK: 'LINK#somehash',
        newPublicKey: pubKey,
        failureCount: 0,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
    });

    const result = await handleGetLinkCodeStatus(TENANT_ID, 'somehash', ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.status).toBe('ready');
    expect(parsed.newPublicKey).toBe(pubKey);
  });

  it('should return 404 for non-existent link code', async () => {
    mockSend.mockResolvedValueOnce({ Item: undefined });

    const result = await handleGetLinkCodeStatus(TENANT_ID, 'badhash', ddb, TABLE_NAME);

    expect(result.statusCode).toBe(404);
  });
});

describe('GET /v1/devices', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should list devices', async () => {
    mockSend.mockResolvedValueOnce({
      Items: [
        { PK: `TENANT#${TENANT_ID}`, SK: 'KEY#fp1', registeredAt: '2026-01-01T00:00:00Z', publicKey: 'pk1' },
        { PK: `TENANT#${TENANT_ID}`, SK: 'KEY#fp2', registeredAt: '2026-02-01T00:00:00Z', publicKey: 'pk2' },
      ],
    });

    const result = await handleListDevices(TENANT_ID, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.devices).toHaveLength(2);
    expect(parsed.devices[0].fingerprint).toBe('fp1');
    expect(parsed.devices[1].fingerprint).toBe('fp2');
  });

  it('should return empty list when no devices', async () => {
    mockSend.mockResolvedValueOnce({ Items: [] });

    const result = await handleListDevices(TENANT_ID, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).devices).toHaveLength(0);
  });
});

describe('DELETE /v1/devices/{fingerprint}', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should delete device, wrapped key, create notification, and audit event', async () => {
    // Two DeleteCommands (KEY# and WRAPPED_KEY#) + one PutCommand (notification) + one PutCommand (audit)
    mockSend.mockResolvedValueOnce({});
    mockSend.mockResolvedValueOnce({});
    mockSend.mockResolvedValueOnce({});
    mockSend.mockResolvedValueOnce({});

    const result = await handleDeleteDevice(TENANT_ID, 'fp-to-remove', ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).status).toBe('deleted');
    expect(mockSend).toHaveBeenCalledTimes(4);
  });
});
