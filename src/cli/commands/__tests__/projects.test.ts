import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Mock keyring storage — projects.ts uses storage.put/delete, not a
// direct KeyringService anymore.
const mockStoragePut = vi.fn().mockResolvedValue(undefined);
const mockStorageDelete = vi.fn().mockResolvedValue(undefined);

vi.mock('@de-otio/keyring', () => {
  class OsKeychainStorage {
    readonly platform = 'node' as const;
    readonly acceptedTiers: readonly string[];
    constructor(opts: { acceptedTiers?: readonly string[] }) {
      this.acceptedTiers = opts.acceptedTiers ?? ['standard'];
    }
    put = mockStoragePut;
    get = vi.fn().mockResolvedValue(null);
    delete = mockStorageDelete;
    list = vi.fn().mockResolvedValue([]);
  }
  class FileSystemStorage {
    readonly platform = 'node' as const;
    readonly acceptedTiers: readonly string[];
    constructor(opts: { acceptedTiers?: readonly string[] }) {
      this.acceptedTiers = opts.acceptedTiers ?? ['standard'];
    }
    put = mockStoragePut;
    get = vi.fn().mockResolvedValue(null);
    delete = mockStorageDelete;
    list = vi.fn().mockResolvedValue([]);
  }
  return { OsKeychainStorage, FileSystemStorage };
});

// Mock SSH signer
const mockSignRequest = vi.fn().mockResolvedValue({
  authorization: 'SSH-Signature c2ln',
  timestamp: '2026-03-20T10:00:00.000Z',
  sequence: 1,
  publicKey: 'dGVzdA==',
});
vi.mock('../../../sync/ssh-signer.js', () => ({
  SSHSigner: class MockSSHSigner {
    constructor(_keyPath?: string) {}
    signRequest = mockSignRequest;
  },
}));

// Mock sequence counter (used by client-factory)
vi.mock('../../../sync/sequence.js', () => ({
  SequenceCounter: class MockSequenceCounter {
    private value = 0;
    next() { return ++this.value; }
    peek() { return this.value; }
  },
}));

// Mock fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

// Mock setup module to use temp dirs
let tmpDir: string;
const mockLoadConfig = vi.fn();
const mockSaveConfig = vi.fn();

vi.mock('../setup.js', () => ({
  get CHAOSKB_DIR() { return tmpDir; },
  loadConfig: (...args: unknown[]) => mockLoadConfig(...args),
  saveConfig: (...args: unknown[]) => mockSaveConfig(...args),
}));

// Stub bootstrap (projects.ts imports CHAOSKB_DIR and KEYRING_SERVICE from
// there). We re-export CHAOSKB_DIR pointing to the test temp dir.
vi.mock('../../bootstrap.js', () => ({
  get CHAOSKB_DIR() { return tmpDir; },
  KEYRING_SERVICE: 'chaoskb',
  FILE_KEY_PATH: '/dev/null/master.key',
  IDENTITY_SECRET_SLOT: 'identity-secret',
  IDENTITY_PUBLIC_SLOT: 'identity-public',
}));

import {
  projectListAvailable,
  projectEnable,
  projectDisable,
  projectAccept,
  projectDecline,
} from '../projects.js';
import type { ChaosKBConfig } from '../../mcp-server.js';

function makeConfig(overrides: Partial<ChaosKBConfig> = {}): ChaosKBConfig {
  return {
    securityTier: 'standard',
    projects: [],
    endpoint: 'https://sync.chaoskb.com',
    sshKeyPath: '/tmp/test-key',
    ...overrides,
  };
}

describe('projects commands', () => {
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chaoskb-projects-test-'));
    vi.clearAllMocks();
    mockSaveConfig.mockResolvedValue(undefined);
    // Default: loadConfig returns a valid config so createSyncClient() works
    mockLoadConfig.mockResolvedValue({
      endpoint: 'https://sync.chaoskb.com',
      sshKeyPath: '/tmp/test-key',
      securityTier: 'standard',
      projects: [],
    });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('projectListAvailable', () => {
    it('returns empty array when no shared projects exist', async () => {
      const config = makeConfig();
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ projects: [] }),
      });

      const result = await projectListAvailable(config);

      expect(result).toEqual([]);
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(mockFetch.mock.calls[0][0]).toContain('/v1/projects/available');
    });

    it('returns project metadata from server', async () => {
      const config = makeConfig();
      const projects = [
        { name: 'team-docs', role: 'editor', owner: '@alice', itemCount: 42 },
        { name: 'shared-kb', role: 'viewer', owner: '@bob', itemCount: 7 },
      ];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ projects }),
      });

      const result = await projectListAvailable(config);

      expect(result).toEqual(projects);
      expect(result).toHaveLength(2);
      expect(result[0].name).toBe('team-docs');
      expect(result[1].role).toBe('viewer');
    });

    it('exits when sync is not configured', async () => {
      const config = makeConfig({ endpoint: undefined });
      const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => {
        throw new Error('process.exit');
      });

      await expect(projectListAvailable(config)).rejects.toThrow('process.exit');
      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });
  });

  describe('projectEnable', () => {
    it('creates project directory and stores key via keyring storage', async () => {
      const config = makeConfig();
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ encryptedKey: Buffer.from('enc-key-data').toString('base64'), algorithm: 'xchacha20' }),
      });

      await projectEnable(config, 'team-docs');

      // Project directory should be created
      const projectDir = path.join(tmpDir, 'projects', 'team-docs');
      expect(fs.existsSync(projectDir)).toBe(true);

      // Key should be stored in keyring storage at the project slot.
      expect(mockStoragePut).toHaveBeenCalledWith(
        'project-team-docs',
        expect.objectContaining({
          v: 1,
          tier: 'standard',
          envelope: expect.any(Uint8Array),
        }),
      );

      // Config should be saved with the new project
      expect(mockSaveConfig).toHaveBeenCalledOnce();
      expect(config.projects).toHaveLength(1);
      expect(config.projects[0].name).toBe('team-docs');
    });

    it('skips if project is already enabled', async () => {
      const config = makeConfig({
        projects: [{ name: 'team-docs', createdAt: '2026-01-01T00:00:00.000Z' }],
      });

      await projectEnable(config, 'team-docs');

      expect(mockFetch).not.toHaveBeenCalled();
      expect(mockSaveConfig).not.toHaveBeenCalled();
    });
  });

  describe('projectDisable', () => {
    it('removes project directory, keyring entry, and config entry', async () => {
      const projectDir = path.join(tmpDir, 'projects', 'team-docs');
      fs.mkdirSync(projectDir, { recursive: true });
      fs.writeFileSync(path.join(projectDir, 'test.db'), 'data');

      const config = makeConfig({
        projects: [{ name: 'team-docs', createdAt: '2026-01-01T00:00:00.000Z' }],
      });

      await projectDisable(config, 'team-docs');

      expect(fs.existsSync(projectDir)).toBe(false);
      expect(mockStorageDelete).toHaveBeenCalledWith('project-team-docs');
      expect(mockSaveConfig).toHaveBeenCalledOnce();
      expect(config.projects).toHaveLength(0);
    });

    it('exits if project is not enabled', async () => {
      const config = makeConfig();
      const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => {
        throw new Error('process.exit');
      });

      await expect(projectDisable(config, 'nonexistent')).rejects.toThrow('process.exit');
      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });
  });

  describe('projectAccept', () => {
    it('accepts invite then enables project', async () => {
      const config = makeConfig();

      // First call: accept invite (POST)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ accepted: true }),
      });

      // Second call: download project key (GET from projectEnable)
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          encryptedKey: Buffer.from('enc-key-data').toString('base64'),
          algorithm: 'xchacha20',
        }),
      });

      await projectAccept(config, 'team-docs');

      expect(mockFetch).toHaveBeenCalledTimes(2);
      // First call should be accept
      expect(mockFetch.mock.calls[0][0]).toContain('/v1/invites/team-docs/accept');
      // Second call should be key download
      expect(mockFetch.mock.calls[1][0]).toContain('/v1/projects/team-docs/key');

      expect(config.projects).toHaveLength(1);
      expect(config.projects[0].name).toBe('team-docs');
    });

    it('exits on server error during accept', async () => {
      const config = makeConfig();
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        text: async () => 'Invite not found',
      });

      const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => {
        throw new Error('process.exit');
      });

      await expect(projectAccept(config, 'nonexistent')).rejects.toThrow('process.exit');
      expect(mockExit).toHaveBeenCalledWith(1);
      mockExit.mockRestore();
    });
  });

  describe('projectDecline', () => {
    it('declines an invite without blocking', async () => {
      const config = makeConfig();
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ declined: true }),
      });

      await projectDecline(config, 'team-docs');

      expect(mockFetch).toHaveBeenCalledOnce();
      expect(mockFetch.mock.calls[0][0]).toContain('/v1/invites/team-docs/decline');
    });

    it('declines an invite with block', async () => {
      const config = makeConfig();
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ declined: true }),
      });

      await projectDecline(config, 'team-docs', '@spammer');

      expect(mockFetch).toHaveBeenCalledOnce();
      expect(mockFetch.mock.calls[0][0]).toContain('/v1/invites/team-docs/decline');
    });
  });
});
