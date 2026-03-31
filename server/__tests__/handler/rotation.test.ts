import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockSend } = vi.hoisted(() => ({ mockSend: vi.fn() }));

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({ send: mockSend }),
  },
  PutCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; this._type = 'PutCommand'; }),
  GetCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; this._type = 'GetCommand'; }),
  UpdateCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; this._type = 'UpdateCommand'; }),
  DeleteCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; this._type = 'DeleteCommand'; }),
  QueryCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; this._type = 'QueryCommand'; }),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn().mockImplementation(function () {}),
}));

import { handleRotateStart, handleRotateConfirm } from '../../lib/handler/routes/rotation.js';

const TABLE_NAME = 'chaoskb-test';
const TENANT_ID = 'test-tenant-123';
const OLD_FINGERPRINT = 'old-fp-abc123';
const NEW_PUBLIC_KEY = Buffer.from('b'.repeat(32)).toString('base64');
const WRAPPED_BLOB = Buffer.from('wrapped-blob-data').toString('base64');

const ddb = { send: mockSend } as any;

describe('POST /v1/rotate-start', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should start rotation successfully', async () => {
    // GetCommand for existing rotation check — none found
    mockSend.mockResolvedValueOnce({ Item: undefined });
    // PutCommand for rotation record
    mockSend.mockResolvedValueOnce({});
    // UpdateCommand for tenant META
    mockSend.mockResolvedValueOnce({});
    // PutCommand for wrapped key
    mockSend.mockResolvedValueOnce({});

    const body = JSON.stringify({ newPublicKey: NEW_PUBLIC_KEY, wrappedBlob: WRAPPED_BLOB });
    const result = await handleRotateStart(TENANT_ID, OLD_FINGERPRINT, body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.status).toBe('rotation_started');
    expect(parsed.newFingerprint).toBeDefined();
    expect(parsed.oldFingerprint).toBe(OLD_FINGERPRINT);
  });

  it('should return 400 when body is missing', async () => {
    const result = await handleRotateStart(TENANT_ID, OLD_FINGERPRINT, null, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('invalid_request');
  });

  it('should return 400 for invalid JSON', async () => {
    const result = await handleRotateStart(TENANT_ID, OLD_FINGERPRINT, 'not json', ddb, TABLE_NAME);

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('invalid_request');
  });

  it('should return 400 when newPublicKey is missing', async () => {
    const body = JSON.stringify({ wrappedBlob: WRAPPED_BLOB });
    const result = await handleRotateStart(TENANT_ID, OLD_FINGERPRINT, body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).message).toContain('newPublicKey');
  });

  it('should return 400 when wrappedBlob is missing', async () => {
    const body = JSON.stringify({ newPublicKey: NEW_PUBLIC_KEY });
    const result = await handleRotateStart(TENANT_ID, OLD_FINGERPRINT, body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).message).toContain('wrappedBlob');
  });

  it('should return 409 when rotation is already in progress', async () => {
    // GetCommand returns existing rotation record
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `TENANT#${TENANT_ID}`,
        SK: 'ROTATION',
        phase: 'started',
      },
    });

    const body = JSON.stringify({ newPublicKey: NEW_PUBLIC_KEY, wrappedBlob: WRAPPED_BLOB });
    const result = await handleRotateStart(TENANT_ID, OLD_FINGERPRINT, body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(409);
    expect(JSON.parse(result.body).error).toBe('rotation_in_progress');
  });
});

describe('POST /v1/rotate-confirm', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should record confirmation when not all devices confirmed', async () => {
    // GetCommand for rotation record
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `TENANT#${TENANT_ID}`,
        SK: 'ROTATION',
        phase: 'started',
        newPublicKey: NEW_PUBLIC_KEY,
        newFingerprint: 'new-fp',
        oldFingerprint: OLD_FINGERPRINT,
        startedAt: new Date().toISOString(),
        confirmations: [],
      },
    });
    // UpdateCommand to add confirmation
    mockSend.mockResolvedValueOnce({});
    // QueryCommand to count devices — 3 devices registered
    mockSend.mockResolvedValueOnce({ Count: 3 });

    const result = await handleRotateConfirm(TENANT_ID, 'device-fp-1', ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.status).toBe('confirmation_recorded');
    expect(parsed.confirmations).toBe(1);
    expect(parsed.totalDevices).toBe(3);
  });

  it('should complete rotation when all devices confirmed', async () => {
    // GetCommand for rotation record — already has 1 confirmation
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `TENANT#${TENANT_ID}`,
        SK: 'ROTATION',
        phase: 'started',
        newPublicKey: NEW_PUBLIC_KEY,
        newFingerprint: 'new-fp',
        oldFingerprint: OLD_FINGERPRINT,
        startedAt: new Date().toISOString(),
        confirmations: ['device-fp-1'],
      },
    });
    // UpdateCommand to add confirmation
    mockSend.mockResolvedValueOnce({});
    // QueryCommand to count devices — 2 devices registered
    mockSend.mockResolvedValueOnce({ Count: 2 });
    // UpdateCommand to update tenant META (completeRotation)
    mockSend.mockResolvedValueOnce({});
    // DeleteCommand to remove old wrapped key (completeRotation)
    mockSend.mockResolvedValueOnce({});
    // DeleteCommand to remove rotation record (completeRotation)
    mockSend.mockResolvedValueOnce({});

    const result = await handleRotateConfirm(TENANT_ID, 'device-fp-2', ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.status).toBe('rotation_complete');
    expect(parsed.confirmations).toBe(2);
  });

  it('should complete rotation after timeout even without all confirmations', async () => {
    const startedAt = new Date(Date.now() - 49 * 60 * 60 * 1000).toISOString(); // 49 hours ago

    // GetCommand for rotation record
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `TENANT#${TENANT_ID}`,
        SK: 'ROTATION',
        phase: 'started',
        newPublicKey: NEW_PUBLIC_KEY,
        newFingerprint: 'new-fp',
        oldFingerprint: OLD_FINGERPRINT,
        startedAt,
        confirmations: [],
      },
    });
    // UpdateCommand to add confirmation
    mockSend.mockResolvedValueOnce({});
    // QueryCommand to count devices — 5 devices registered
    mockSend.mockResolvedValueOnce({ Count: 5 });
    // UpdateCommand to update tenant META (completeRotation)
    mockSend.mockResolvedValueOnce({});
    // DeleteCommand to remove old wrapped key (completeRotation)
    mockSend.mockResolvedValueOnce({});
    // DeleteCommand to remove rotation record (completeRotation)
    mockSend.mockResolvedValueOnce({});

    const result = await handleRotateConfirm(TENANT_ID, 'device-fp-1', ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.status).toBe('rotation_complete');
  });

  it('should return 404 when no rotation in progress', async () => {
    // GetCommand returns no rotation record
    mockSend.mockResolvedValueOnce({ Item: undefined });

    const result = await handleRotateConfirm(TENANT_ID, 'device-fp-1', ddb, TABLE_NAME);

    expect(result.statusCode).toBe(404);
    expect(JSON.parse(result.body).error).toBe('not_found');
  });

  it('should not duplicate fingerprint in confirmations', async () => {
    // GetCommand — fingerprint already in confirmations
    mockSend.mockResolvedValueOnce({
      Item: {
        PK: `TENANT#${TENANT_ID}`,
        SK: 'ROTATION',
        phase: 'started',
        newPublicKey: NEW_PUBLIC_KEY,
        newFingerprint: 'new-fp',
        oldFingerprint: OLD_FINGERPRINT,
        startedAt: new Date().toISOString(),
        confirmations: ['device-fp-1'],
      },
    });
    // QueryCommand to count devices — 3 devices
    mockSend.mockResolvedValueOnce({ Count: 3 });

    const result = await handleRotateConfirm(TENANT_ID, 'device-fp-1', ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.status).toBe('confirmation_recorded');
    expect(parsed.confirmations).toBe(1);
  });
});
