import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { mockSend } = vi.hoisted(() => ({ mockSend: vi.fn() }));

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: () => ({ send: mockSend }),
  },
  PutCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
  GetCommand: vi.fn().mockImplementation(function (this: any, input: any) { this.input = input; }),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: vi.fn().mockImplementation(function () {}),
}));

import {
  fetchGitHubKeys,
  verifyKeyOnGitHub,
  storeGitHubAssociation,
  findTenantByGitHub,
  storeGitHubReverseLookup,
  GitHubVerificationError,
  _resetGitHubKeyCache,
} from '../../lib/handler/routes/github.js';

const TABLE_NAME = 'chaoskb-test';
const ddb = { send: mockSend } as any;

// Mock global fetch
const originalFetch = globalThis.fetch;

describe('GitHub key verification', () => {
  beforeEach(() => {
    mockSend.mockReset();
    _resetGitHubKeyCache();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('fetchGitHubKeys', () => {
    it('should parse GitHub keys (one per line)', async () => {
      globalThis.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => 'ssh-ed25519 AAAAC3key1 user@host\nssh-rsa AAAAB3key2\n',
      });

      const keys = await fetchGitHubKeys('testuser');
      expect(keys).toEqual([
        'ssh-ed25519 AAAAC3key1 user@host',
        'ssh-rsa AAAAB3key2',
      ]);
    });

    it('should throw for 404 (user not found)', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });

      await expect(fetchGitHubKeys('nonexistent')).rejects.toThrow(GitHubVerificationError);
      await expect(fetchGitHubKeys('nonexistent2')).rejects.toThrow('not found');
    });

    it('should cache results for 5 minutes', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        text: async () => 'ssh-ed25519 cachedkey\n',
      });
      globalThis.fetch = mockFetch;

      await fetchGitHubKeys('cacheduser');
      await fetchGitHubKeys('cacheduser');

      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('verifyKeyOnGitHub', () => {
    it('should return true when key is found on GitHub', async () => {
      globalThis.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => 'ssh-ed25519 AAAAC3matchkey user@host\nssh-rsa AAAAB3otherkey\n',
      });

      const result = await verifyKeyOnGitHub('AAAAC3matchkey', 'testuser');
      expect(result).toBe(true);
    });

    it('should return false when key is not on GitHub', async () => {
      globalThis.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => 'ssh-ed25519 AAAAC3otherkey user@host\n',
      });

      const result = await verifyKeyOnGitHub('AAAAC3nomatchkey', 'testuser');
      expect(result).toBe(false);
    });
  });

  describe('storeGitHubAssociation', () => {
    it('should store TENANT#{id}/GITHUB#{username}', async () => {
      mockSend.mockResolvedValueOnce({});

      await storeGitHubAssociation('tenant-123', 'ghuser', ddb, TABLE_NAME);

      expect(mockSend).toHaveBeenCalledTimes(1);
    });
  });

  describe('findTenantByGitHub', () => {
    it('should return tenantId when association exists', async () => {
      mockSend.mockResolvedValueOnce({
        Item: { PK: 'GITHUB#ghuser', SK: 'META', tenantId: 'tenant-123' },
      });

      const result = await findTenantByGitHub('ghuser', ddb, TABLE_NAME);
      expect(result).toBe('tenant-123');
    });

    it('should return null when no association', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });

      const result = await findTenantByGitHub('unknown', ddb, TABLE_NAME);
      expect(result).toBeNull();
    });
  });

  describe('storeGitHubReverseLookup', () => {
    it('should store GITHUB#{username} -> tenantId', async () => {
      mockSend.mockResolvedValueOnce({});

      await storeGitHubReverseLookup('ghuser', 'tenant-123', ddb, TABLE_NAME);

      expect(mockSend).toHaveBeenCalledTimes(1);
    });
  });
});
