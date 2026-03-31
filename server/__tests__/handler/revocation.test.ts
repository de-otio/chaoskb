import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockSend = vi.hoisted(() => vi.fn());

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({ send: mockSend }),
  },
  PutCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  QueryCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  BatchWriteCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn().mockImplementation(function () {}),
}));

import { handleRevokeAll } from '../../lib/handler/routes/revocation.js';

const TABLE_NAME = 'chaoskb-test';
const TENANT_ID = 'test-tenant-123';
const PK = `TENANT#${TENANT_ID}`;
const ddb = { send: mockSend } as any;

describe('handleRevokeAll', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should delete KEY#, WRAPPED_KEY#, ROTATION, and SEQUENCE# items', async () => {
    // Query returns mixed items
    mockSend.mockResolvedValueOnce({
      Items: [
        { PK, SK: 'META' },
        { PK, SK: 'KEY#fp1' },
        { PK, SK: 'KEY#fp2' },
        { PK, SK: 'WRAPPED_KEY#fp1' },
        { PK, SK: 'WRAPPED_KEY#fp2' },
        { PK, SK: 'ROTATION' },
        { PK, SK: 'SEQUENCE#fp1' },
        { PK, SK: 'SEQUENCE#fp2' },
        { PK, SK: 'BLOB#some-blob' },
        { PK, SK: 'AUDIT#2025-01-01T00:00:00Z#aaa' },
      ],
    });
    // BatchWriteCommand for deletions
    mockSend.mockResolvedValueOnce({});
    // PutCommand for audit log
    mockSend.mockResolvedValueOnce({});

    const result = await handleRevokeAll(TENANT_ID, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.status).toBe('revoked');
    expect(parsed.message).toContain('Re-register');

    // Verify BatchWriteCommand was called with correct items (not META, BLOB, or AUDIT)
    const batchCall = mockSend.mock.calls[1][0];
    const deleteRequests = batchCall.input.RequestItems[TABLE_NAME];
    const deletedSKs = deleteRequests.map((r: any) => r.DeleteRequest.Key.SK);

    expect(deletedSKs).toContain('KEY#fp1');
    expect(deletedSKs).toContain('KEY#fp2');
    expect(deletedSKs).toContain('WRAPPED_KEY#fp1');
    expect(deletedSKs).toContain('WRAPPED_KEY#fp2');
    expect(deletedSKs).toContain('ROTATION');
    expect(deletedSKs).toContain('SEQUENCE#fp1');
    expect(deletedSKs).toContain('SEQUENCE#fp2');
    expect(deletedSKs).not.toContain('META');
    expect(deletedSKs).not.toContain('BLOB#some-blob');
    expect(deletedSKs).not.toContain('AUDIT#2025-01-01T00:00:00Z#aaa');
    expect(deleteRequests).toHaveLength(7);
  });

  it('should handle tenant with no revocable items', async () => {
    // Query returns only META
    mockSend.mockResolvedValueOnce({
      Items: [{ PK, SK: 'META' }],
    });
    // PutCommand for audit log
    mockSend.mockResolvedValueOnce({});

    const result = await handleRevokeAll(TENANT_ID, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    // Should have been called twice: query + audit log (no batch delete needed)
    expect(mockSend).toHaveBeenCalledTimes(2);
  });

  it('should log an audit event after revocation', async () => {
    mockSend.mockResolvedValueOnce({ Items: [] });
    // PutCommand for audit log
    mockSend.mockResolvedValueOnce({});

    await handleRevokeAll(TENANT_ID, ddb, TABLE_NAME);

    // Last call should be the audit log PutCommand
    const auditCall = mockSend.mock.calls[mockSend.mock.calls.length - 1][0];
    expect(auditCall.input.Item.eventType).toBe('revoked');
    expect(auditCall.input.Item.fingerprint).toBe('all');
    expect(auditCall.input.Item.PK).toBe(PK);
    expect(auditCall.input.Item.SK).toMatch(/^AUDIT#/);
  });

  it('should batch delete in groups of 25', async () => {
    // Create 30 revocable items
    const items = [{ PK, SK: 'META' }];
    for (let i = 0; i < 30; i++) {
      items.push({ PK, SK: `KEY#fp${i}` });
    }
    mockSend.mockResolvedValueOnce({ Items: items });
    // Two batch deletes
    mockSend.mockResolvedValueOnce({});
    mockSend.mockResolvedValueOnce({});
    // Audit log
    mockSend.mockResolvedValueOnce({});

    await handleRevokeAll(TENANT_ID, ddb, TABLE_NAME);

    // query + 2 batch deletes + audit = 4 calls
    expect(mockSend).toHaveBeenCalledTimes(4);

    // First batch should have 25 items
    const batch1 = mockSend.mock.calls[1][0];
    expect(batch1.input.RequestItems[TABLE_NAME]).toHaveLength(25);

    // Second batch should have 5 items
    const batch2 = mockSend.mock.calls[2][0];
    expect(batch2.input.RequestItems[TABLE_NAME]).toHaveLength(5);
  });
});
