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
  handleCreateInvite,
  handleListInvites,
  handleAcceptInvite,
  handleDeclineInvite,
} from '../../lib/handler/routes/invites.js';

const TABLE_NAME = 'chaoskb-test';
const TENANT_ID = 'test-tenant-abc';
const FINGERPRINT = 'sender-fp-123';
const RECIPIENT_FP = 'recipient-fp-456';
const PROJECT_TENANT_ID = 'project-tenant-xyz';
const ddb = { send: mockSend } as any;

function validCreateBody(overrides: Record<string, unknown> = {}) {
  return JSON.stringify({
    recipientFingerprint: RECIPIENT_FP,
    projectTenantId: PROJECT_TENANT_ID,
    encryptedPayload: Buffer.from('test-payload').toString('base64'),
    role: 'editor',
    ...overrides,
  });
}

describe('POST /v1/invites (handleCreateInvite)', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should create an invite (201)', async () => {
    // Rate limit: hourly counter
    mockSend.mockResolvedValueOnce({ Attributes: { count: 1 } });
    // Rate limit: daily counter
    mockSend.mockResolvedValueOnce({ Attributes: { count: 1 } });
    // Recipient pending count query
    mockSend.mockResolvedValueOnce({ Count: 0 });
    // PutCommand: store invite
    mockSend.mockResolvedValueOnce({});
    // PutCommand: audit event
    mockSend.mockResolvedValueOnce({});

    const result = await handleCreateInvite(TENANT_ID, FINGERPRINT, validCreateBody(), ddb, TABLE_NAME);

    expect(result.statusCode).toBe(201);
    const parsed = JSON.parse(result.body);
    expect(parsed.inviteId).toBeDefined();
    expect(parsed.status).toBe('pending');
    expect(mockSend).toHaveBeenCalledTimes(5);
  });

  it('should return 400 for missing body', async () => {
    const result = await handleCreateInvite(TENANT_ID, FINGERPRINT, null, ddb, TABLE_NAME);
    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('invalid_request');
  });

  it('should return 400 for invalid JSON', async () => {
    const result = await handleCreateInvite(TENANT_ID, FINGERPRINT, '{bad', ddb, TABLE_NAME);
    expect(result.statusCode).toBe(400);
  });

  it('should return 400 for missing required fields', async () => {
    const result = await handleCreateInvite(
      TENANT_ID, FINGERPRINT,
      JSON.stringify({ recipientFingerprint: RECIPIENT_FP }),
      ddb, TABLE_NAME,
    );
    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).error).toBe('invalid_request');
  });

  it('should return 400 for invalid base64 payload', async () => {
    const result = await handleCreateInvite(
      TENANT_ID, FINGERPRINT,
      validCreateBody({ encryptedPayload: 'not valid base64!!!' }),
      ddb, TABLE_NAME,
    );
    expect(result.statusCode).toBe(400);
    expect(JSON.parse(result.body).message).toContain('base64');
  });

  it('should return 429 when hourly rate limit exceeded', async () => {
    // Hourly counter returns count > 10
    mockSend.mockResolvedValueOnce({ Attributes: { count: 11 } });

    const result = await handleCreateInvite(TENANT_ID, FINGERPRINT, validCreateBody(), ddb, TABLE_NAME);

    expect(result.statusCode).toBe(429);
    expect(JSON.parse(result.body).error).toBe('rate_limited');
  });

  it('should return 429 when daily rate limit exceeded', async () => {
    // Hourly: OK
    mockSend.mockResolvedValueOnce({ Attributes: { count: 5 } });
    // Daily: exceeded
    mockSend.mockResolvedValueOnce({ Attributes: { count: 51 } });

    const result = await handleCreateInvite(TENANT_ID, FINGERPRINT, validCreateBody(), ddb, TABLE_NAME);

    expect(result.statusCode).toBe(429);
    expect(JSON.parse(result.body).message).toContain('Daily');
  });

  it('should return 409 when recipient has too many pending invites', async () => {
    // Rate limits OK
    mockSend.mockResolvedValueOnce({ Attributes: { count: 1 } });
    mockSend.mockResolvedValueOnce({ Attributes: { count: 1 } });
    // Recipient has 20 pending
    mockSend.mockResolvedValueOnce({ Count: 20 });

    const result = await handleCreateInvite(TENANT_ID, FINGERPRINT, validCreateBody(), ddb, TABLE_NAME);

    expect(result.statusCode).toBe(409);
    expect(JSON.parse(result.body).error).toBe('recipient_limit');
  });
});

describe('GET /v1/invites (handleListInvites)', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  it('should list pending invites for the authenticated user', async () => {
    mockSend.mockResolvedValueOnce({
      Items: [
        {
          inviteId: 'inv-1',
          senderFingerprint: 'sender-1',
          projectTenantId: 'proj-1',
          role: 'editor',
          createdAt: '2026-03-01T00:00:00Z',
          status: 'pending',
          expiresAt: new Date(Date.now() + 86400000).toISOString(),
        },
        {
          inviteId: 'inv-2',
          senderFingerprint: 'sender-2',
          projectTenantId: 'proj-2',
          role: 'viewer',
          createdAt: '2026-03-02T00:00:00Z',
          status: 'pending',
          expiresAt: new Date(Date.now() + 86400000).toISOString(),
        },
      ],
    });

    const result = await handleListInvites(TENANT_ID, RECIPIENT_FP, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.invites).toHaveLength(2);
    expect(parsed.invites[0].inviteId).toBe('inv-1');
    expect(parsed.invites[1].role).toBe('viewer');
  });

  it('should return empty list when no pending invites', async () => {
    mockSend.mockResolvedValueOnce({ Items: [] });

    const result = await handleListInvites(TENANT_ID, RECIPIENT_FP, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).invites).toHaveLength(0);
  });
});

describe('POST /v1/invites/{id}/accept (handleAcceptInvite)', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  const INVITE_ID = 'inv-accept-test';

  function pendingInvite(overrides: Record<string, unknown> = {}) {
    return {
      PK: `INVITE#${INVITE_ID}`,
      SK: 'META',
      inviteId: INVITE_ID,
      status: 'pending',
      senderFingerprint: FINGERPRINT,
      recipientFingerprint: RECIPIENT_FP,
      projectTenantId: PROJECT_TENANT_ID,
      encryptedPayload: Buffer.from('secret').toString('base64'),
      role: 'editor',
      createdAt: '2026-03-01T00:00:00Z',
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      ...overrides,
    };
  }

  it('should accept a pending invite (200)', async () => {
    // GetCommand: fetch invite
    mockSend.mockResolvedValueOnce({ Item: pendingInvite() });
    // UpdateCommand: set accepted
    mockSend.mockResolvedValueOnce({});
    // PutCommand: audit event
    mockSend.mockResolvedValueOnce({});

    const result = await handleAcceptInvite(TENANT_ID, RECIPIENT_FP, INVITE_ID, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    const parsed = JSON.parse(result.body);
    expect(parsed.status).toBe('accepted');
    expect(parsed.encryptedPayload).toBeDefined();
    expect(parsed.projectTenantId).toBe(PROJECT_TENANT_ID);
  });

  it('should return already_accepted for idempotent re-accept', async () => {
    mockSend.mockResolvedValueOnce({
      Item: pendingInvite({ status: 'accepted' }),
    });

    const result = await handleAcceptInvite(TENANT_ID, RECIPIENT_FP, INVITE_ID, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).status).toBe('already_accepted');
    // No UpdateCommand or audit event should be called
    expect(mockSend).toHaveBeenCalledTimes(1);
  });

  it('should return 404 for non-existent invite', async () => {
    mockSend.mockResolvedValueOnce({ Item: undefined });

    const result = await handleAcceptInvite(TENANT_ID, RECIPIENT_FP, 'no-such-id', ddb, TABLE_NAME);

    expect(result.statusCode).toBe(404);
    expect(JSON.parse(result.body).error).toBe('not_found');
  });

  it('should return 403 when fingerprint does not match recipient', async () => {
    mockSend.mockResolvedValueOnce({ Item: pendingInvite() });

    const result = await handleAcceptInvite(TENANT_ID, 'wrong-fingerprint', INVITE_ID, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(403);
    expect(JSON.parse(result.body).error).toBe('forbidden');
  });

  it('should return 409 for already declined invite', async () => {
    mockSend.mockResolvedValueOnce({
      Item: pendingInvite({ status: 'declined' }),
    });

    const result = await handleAcceptInvite(TENANT_ID, RECIPIENT_FP, INVITE_ID, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(409);
    expect(JSON.parse(result.body).error).toBe('conflict');
  });

  it('should return 410 for expired invite', async () => {
    mockSend.mockResolvedValueOnce({
      Item: pendingInvite({ expiresAt: new Date(Date.now() - 60000).toISOString() }),
    });

    const result = await handleAcceptInvite(TENANT_ID, RECIPIENT_FP, INVITE_ID, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(410);
    expect(JSON.parse(result.body).error).toBe('expired');
  });
});

describe('POST /v1/invites/{id}/decline (handleDeclineInvite)', () => {
  beforeEach(() => {
    mockSend.mockReset();
  });

  const INVITE_ID = 'inv-decline-test';

  function pendingInvite(overrides: Record<string, unknown> = {}) {
    return {
      PK: `INVITE#${INVITE_ID}`,
      SK: 'META',
      inviteId: INVITE_ID,
      status: 'pending',
      senderFingerprint: FINGERPRINT,
      recipientFingerprint: RECIPIENT_FP,
      projectTenantId: PROJECT_TENANT_ID,
      encryptedPayload: Buffer.from('secret').toString('base64'),
      role: 'editor',
      createdAt: '2026-03-01T00:00:00Z',
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      ...overrides,
    };
  }

  it('should decline a pending invite (200)', async () => {
    // GetCommand: fetch invite
    mockSend.mockResolvedValueOnce({ Item: pendingInvite() });
    // UpdateCommand: set declined
    mockSend.mockResolvedValueOnce({});
    // PutCommand: audit event
    mockSend.mockResolvedValueOnce({});

    const result = await handleDeclineInvite(TENANT_ID, RECIPIENT_FP, INVITE_ID, null, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).status).toBe('declined');
  });

  it('should decline and block sender when block=true', async () => {
    // GetCommand: fetch invite
    mockSend.mockResolvedValueOnce({ Item: pendingInvite() });
    // UpdateCommand: set declined
    mockSend.mockResolvedValueOnce({});
    // PutCommand: block record
    mockSend.mockResolvedValueOnce({});
    // PutCommand: audit event
    mockSend.mockResolvedValueOnce({});

    const body = JSON.stringify({ block: true, senderFingerprint: FINGERPRINT });
    const result = await handleDeclineInvite(TENANT_ID, RECIPIENT_FP, INVITE_ID, body, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(200);
    expect(JSON.parse(result.body).status).toBe('declined');
    // 1 Get + 1 Update (decline) + 1 Put (block) + 1 Put (audit) = 4 calls
    expect(mockSend).toHaveBeenCalledTimes(4);
  });

  it('should return 404 for non-existent invite', async () => {
    mockSend.mockResolvedValueOnce({ Item: undefined });

    const result = await handleDeclineInvite(TENANT_ID, RECIPIENT_FP, 'no-such-id', null, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(404);
  });

  it('should return 403 when fingerprint does not match recipient', async () => {
    mockSend.mockResolvedValueOnce({ Item: pendingInvite() });

    const result = await handleDeclineInvite(TENANT_ID, 'wrong-fp', INVITE_ID, null, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(403);
  });

  it('should return 409 for already accepted invite', async () => {
    mockSend.mockResolvedValueOnce({
      Item: pendingInvite({ status: 'accepted' }),
    });

    const result = await handleDeclineInvite(TENANT_ID, RECIPIENT_FP, INVITE_ID, null, ddb, TABLE_NAME);

    expect(result.statusCode).toBe(409);
    expect(JSON.parse(result.body).error).toBe('conflict');
  });
});
