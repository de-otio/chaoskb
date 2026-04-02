import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockSend } = vi.hoisted(() => ({ mockSend: vi.fn() }));

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({ send: mockSend }),
  },
  UpdateCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn().mockImplementation(function () {}),
}));

import { checkRateLimit, checkIpRateLimit, rateLimitHeaders } from '../../lib/handler/middleware/rate-limit.js';

const TABLE_NAME = 'chaoskb-test';
const TENANT_ID = 'test-tenant-123';
const ddb = { send: mockSend } as any;

describe('checkRateLimit', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should allow request under limit', async () => {
    mockSend.mockResolvedValueOnce({ Attributes: { count: 5 } });

    const result = await checkRateLimit(TENANT_ID, 'PUT', ddb, TABLE_NAME);

    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(95); // 100 - 5
    expect(result.retryAfter).toBeUndefined();
  });

  it('should reject request over PUT limit (100/min)', async () => {
    mockSend.mockResolvedValueOnce({ Attributes: { count: 101 } });

    const result = await checkRateLimit(TENANT_ID, 'PUT', ddb, TABLE_NAME);

    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retryAfter).toBeGreaterThan(0);
  });

  it('should reject request over GET limit (1000/min)', async () => {
    mockSend.mockResolvedValueOnce({ Attributes: { count: 1001 } });

    const result = await checkRateLimit(TENANT_ID, 'GET', ddb, TABLE_NAME);

    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it('should reject request over DELETE limit (100/min)', async () => {
    mockSend.mockResolvedValueOnce({ Attributes: { count: 101 } });

    const result = await checkRateLimit(TENANT_ID, 'DELETE', ddb, TABLE_NAME);

    expect(result.allowed).toBe(false);
  });

  it('should reject request over LIST limit (100/min)', async () => {
    mockSend.mockResolvedValueOnce({ Attributes: { count: 101 } });

    const result = await checkRateLimit(TENANT_ID, 'LIST', ddb, TABLE_NAME);

    expect(result.allowed).toBe(false);
  });

  it('should have different limits for different operations', async () => {
    // PUT at 100 — should be at the limit
    mockSend.mockResolvedValueOnce({ Attributes: { count: 100 } });
    const putResult = await checkRateLimit(TENANT_ID, 'PUT', ddb, TABLE_NAME);
    expect(putResult.allowed).toBe(true);
    expect(putResult.remaining).toBe(0);

    // GET at 100 — should still have plenty of room (1000 limit)
    mockSend.mockResolvedValueOnce({ Attributes: { count: 100 } });
    const getResult = await checkRateLimit(TENANT_ID, 'GET', ddb, TABLE_NAME);
    expect(getResult.allowed).toBe(true);
    expect(getResult.remaining).toBe(900); // 1000 - 100
  });
});

describe('checkIpRateLimit — REGISTER_GITHUB', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should allow up to 5 requests per 60-second window', async () => {
    mockSend.mockResolvedValueOnce({ Attributes: { count: 5 } });

    const result = await checkIpRateLimit('1.2.3.4', 'REGISTER_GITHUB', ddb, TABLE_NAME);

    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(0); // 5 - 5
  });

  it('should reject 6th GitHub registration attempt within window', async () => {
    mockSend.mockResolvedValueOnce({ Attributes: { count: 6 } });

    const result = await checkIpRateLimit('1.2.3.4', 'REGISTER_GITHUB', ddb, TABLE_NAME);

    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retryAfter).toBeGreaterThan(0);
  });

  it('should not affect non-GitHub registrations (default 1/sec)', async () => {
    // REGISTER uses 1-second windows with limit 1
    mockSend.mockResolvedValueOnce({ Attributes: { count: 1 } });

    const result = await checkIpRateLimit('1.2.3.4', 'REGISTER', ddb, TABLE_NAME);

    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(0); // 1 - 1

    // 2nd request in same second rejected
    mockSend.mockResolvedValueOnce({ Attributes: { count: 2 } });

    const result2 = await checkIpRateLimit('1.2.3.4', 'REGISTER', ddb, TABLE_NAME);

    expect(result2.allowed).toBe(false);
  });
});

describe('rateLimitHeaders', () => {
  it('should include remaining header when allowed', () => {
    const headers = rateLimitHeaders({ allowed: true, remaining: 50 });
    expect(headers['X-RateLimit-Remaining']).toBe('50');
    expect(headers['Retry-After']).toBeUndefined();
  });

  it('should include Retry-After when rejected', () => {
    const headers = rateLimitHeaders({ allowed: false, remaining: 0, retryAfter: 30 });
    expect(headers['X-RateLimit-Remaining']).toBe('0');
    expect(headers['Retry-After']).toBe('30');
  });
});
