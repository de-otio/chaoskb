import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockSend = vi.hoisted(() => vi.fn());

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({ send: mockSend }),
  },
  PutCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  QueryCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn().mockImplementation(function () {}),
}));

import { logAuditEvent, handleGetAuditLog } from '../../lib/handler/routes/audit.js';

const TABLE_NAME = 'chaoskb-test';
const TENANT_ID = 'test-tenant-123';
const ddb = { send: mockSend } as any;

describe('logAuditEvent', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should write an audit event to DynamoDB with correct PK/SK and TTL', async () => {
    mockSend.mockResolvedValueOnce({});

    await logAuditEvent(ddb, TABLE_NAME, TENANT_ID, {
      eventType: 'registered',
      fingerprint: 'abc123',
      metadata: { publicKey: 'key-data' },
    });

    expect(mockSend).toHaveBeenCalledTimes(1);
    const putCmd = mockSend.mock.calls[0][0];
    const item = putCmd.input.Item;

    expect(putCmd.input.TableName).toBe(TABLE_NAME);
    expect(item.PK).toBe(`TENANT#${TENANT_ID}`);
    expect(item.SK).toMatch(/^AUDIT#\d{4}-\d{2}-\d{2}T.+#[0-9a-f]{12}$/);
    expect(item.eventType).toBe('registered');
    expect(item.fingerprint).toBe('abc123');
    expect(item.metadata).toEqual({ publicKey: 'key-data' });
    expect(item.timestamp).toBeDefined();
    expect(item.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('should handle events without metadata', async () => {
    mockSend.mockResolvedValueOnce({});

    await logAuditEvent(ddb, TABLE_NAME, TENANT_ID, {
      eventType: 'revoked',
      fingerprint: 'all',
    });

    expect(mockSend).toHaveBeenCalledTimes(1);
    const putCmd = mockSend.mock.calls[0][0];
    expect(putCmd.input.Item.eventType).toBe('revoked');
    expect(putCmd.input.Item.metadata).toBeUndefined();
  });
});

describe('handleGetAuditLog', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should return sorted audit events', async () => {
    mockSend.mockResolvedValueOnce({
      Items: [
        {
          PK: `TENANT#${TENANT_ID}`,
          SK: 'AUDIT#2025-01-01T00:00:00.000Z#aaa111',
          eventType: 'registered',
          fingerprint: 'fp1',
          metadata: { publicKey: 'key1' },
          timestamp: '2025-01-01T00:00:00.000Z',
        },
        {
          PK: `TENANT#${TENANT_ID}`,
          SK: 'AUDIT#2025-01-02T00:00:00.000Z#bbb222',
          eventType: 'revoked',
          fingerprint: 'all',
          metadata: { deletedItems: 3 },
          timestamp: '2025-01-02T00:00:00.000Z',
        },
      ],
    });

    const result = await handleGetAuditLog(TENANT_ID, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.events).toHaveLength(2);
    expect(parsed.events[0].eventType).toBe('registered');
    expect(parsed.events[1].eventType).toBe('revoked');
  });

  it('should return empty array when no audit events exist', async () => {
    mockSend.mockResolvedValueOnce({ Items: [] });

    const result = await handleGetAuditLog(TENANT_ID, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.events).toEqual([]);
  });

  it('should query with correct key condition', async () => {
    mockSend.mockResolvedValueOnce({ Items: [] });

    await handleGetAuditLog(TENANT_ID, ddb, TABLE_NAME);

    expect(mockSend).toHaveBeenCalledTimes(1);
    const queryCmd = mockSend.mock.calls[0][0];
    expect(queryCmd.input.KeyConditionExpression).toBe('PK = :pk AND begins_with(SK, :prefix)');
    expect(queryCmd.input.ExpressionAttributeValues[':pk']).toBe(`TENANT#${TENANT_ID}`);
    expect(queryCmd.input.ExpressionAttributeValues[':prefix']).toBe('AUDIT#');
    expect(queryCmd.input.ScanIndexForward).toBe(true);
  });
});
