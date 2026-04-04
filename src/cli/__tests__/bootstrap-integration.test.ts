/**
 * Integration tests for the bootstrap module.
 *
 * Uses real temp directories but mocks crypto/keyring/database
 * to avoid requiring native modules in CI.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Mock the dynamic imports that bootstrap uses
const mockKeyringStore = vi.fn().mockResolvedValue(undefined);
vi.mock('../../crypto/keyring.js', () => ({
  KeyringService: class {
    store = mockKeyringStore;
    retrieve = vi.fn().mockResolvedValue(null);
    delete = vi.fn().mockResolvedValue(true);
  },
}));

const mockMasterKey = {
  buffer: Buffer.alloc(32, 0xab),
  length: 32,
  isDisposed: false,
  dispose: vi.fn(),
};
vi.mock('../../crypto/encryption-service.js', () => ({
  EncryptionService: class {
    generateMasterKey = vi.fn().mockReturnValue(mockMasterKey);
  },
}));

const mockDbClose = vi.fn();
const mockDbManagerCloseAll = vi.fn();
vi.mock('../../storage/database-manager.js', () => ({
  DatabaseManager: class {
    constructor() { /* no-op */ }
    getPersonalDb = vi.fn().mockReturnValue({ close: mockDbClose });
    closeAll = mockDbManagerCloseAll;
  },
}));

import { bootstrap } from '../bootstrap.js';

describe('bootstrap', () => {
  let tmpDir: string;
  let chaoskbDir: string;

  let stderrWriteSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chaoskb-bootstrap-test-'));
    chaoskbDir = path.join(tmpDir, '.chaoskb');
    vi.clearAllMocks();
    mockMasterKey.isDisposed = false;
    mockMasterKey.dispose = vi.fn();
    // Suppress stderr output (macOS keychain message, warnings)
    stderrWriteSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stderrWriteSpy.mockRestore();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should create directory structure, store key, and write config', async () => {
    await bootstrap({ baseDir: chaoskbDir });

    // Directory exists with correct structure
    expect(fs.existsSync(chaoskbDir)).toBe(true);
    expect(fs.existsSync(path.join(chaoskbDir, 'models'))).toBe(true);

    // Config written
    const configPath = path.join(chaoskbDir, 'config.json');
    expect(fs.existsSync(configPath)).toBe(true);
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(config.securityTier).toBe('standard');
    expect(config.projects).toEqual([]);

    // Config has secure permissions (0o600) — skip on Windows where chmod is a no-op
    if (process.platform !== 'win32') {
      const configStat = fs.statSync(configPath);
      expect(configStat.mode & 0o777).toBe(0o600);
    }

    // Key stored in keyring (master key + identity keypair = 3 store calls)
    expect(mockKeyringStore).toHaveBeenCalledWith('chaoskb', 'master-key', mockMasterKey);

    // Master key disposed
    expect(mockMasterKey.dispose).toHaveBeenCalled();

    // Database initialized and closed
    expect(mockDbClose).toHaveBeenCalled();
    expect(mockDbManagerCloseAll).toHaveBeenCalled();
  });

  it('should be idempotent — no-op if config.json already exists', async () => {
    // Pre-create config
    fs.mkdirSync(chaoskbDir, { recursive: true });
    fs.writeFileSync(
      path.join(chaoskbDir, 'config.json'),
      JSON.stringify({ securityTier: 'standard', projects: [] }),
    );

    await bootstrap({ baseDir: chaoskbDir });

    // Should not have attempted to generate key or init DB
    expect(mockKeyringStore).not.toHaveBeenCalled();
    expect(mockDbClose).not.toHaveBeenCalled();
  });

  it('should fall back to file-based key when keyring fails and env var set', async () => {
    mockKeyringStore.mockRejectedValueOnce(new Error('Keyring unavailable'));

    const originalEnv = process.env.CHAOSKB_KEY_STORAGE;
    process.env.CHAOSKB_KEY_STORAGE = 'file';

    try {
      await bootstrap({ baseDir: chaoskbDir });

      // File-based key written
      const keyPath = path.join(chaoskbDir, 'master.key');
      expect(fs.existsSync(keyPath)).toBe(true);
      const keyHex = fs.readFileSync(keyPath, 'utf-8');
      expect(keyHex).toBe(mockMasterKey.buffer.toString('hex'));

      // Key file has secure permissions (0o600) — skip on Windows
      if (process.platform !== 'win32') {
        const keyStat = fs.statSync(keyPath);
        expect(keyStat.mode & 0o777).toBe(0o600);
      }

      // Warning emitted
      expect(stderrWriteSpy).toHaveBeenCalledWith(
        expect.stringContaining('OS keyring unavailable'),
      );

      // Config still written
      expect(fs.existsSync(path.join(chaoskbDir, 'config.json'))).toBe(true);
    } finally {
      if (originalEnv === undefined) {
        delete process.env.CHAOSKB_KEY_STORAGE;
      } else {
        process.env.CHAOSKB_KEY_STORAGE = originalEnv;
      }
    }
  });

  it('should throw when keyring fails and env var not set', async () => {
    mockKeyringStore.mockRejectedValueOnce(new Error('Keyring unavailable'));

    const originalEnv = process.env.CHAOSKB_KEY_STORAGE;
    delete process.env.CHAOSKB_KEY_STORAGE;

    try {
      await expect(bootstrap({ baseDir: chaoskbDir })).rejects.toThrow(
        'Failed to store master key in OS keyring',
      );

      // Config should NOT have been written (bootstrap failed)
      expect(fs.existsSync(path.join(chaoskbDir, 'config.json'))).toBe(false);

      // Master key should be disposed even on failure
      expect(mockMasterKey.dispose).toHaveBeenCalled();
    } finally {
      if (originalEnv !== undefined) {
        process.env.CHAOSKB_KEY_STORAGE = originalEnv;
      }
    }
  });

  it('should handle double-check pattern after lock acquisition', async () => {
    // Simulate another process creating config between existsSync check and lock acquisition
    // by pre-creating the config before bootstrap runs, but after the directory exists
    fs.mkdirSync(chaoskbDir, { recursive: true });

    // First call creates config (stores master key, and optionally identity keypair)
    await bootstrap({ baseDir: chaoskbDir });
    expect(mockKeyringStore).toHaveBeenCalled();

    vi.clearAllMocks();

    // Second call should no-op (idempotent)
    await bootstrap({ baseDir: chaoskbDir });
    expect(mockKeyringStore).not.toHaveBeenCalled();
  });
});
