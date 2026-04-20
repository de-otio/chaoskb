/**
 * Integration tests for the bootstrap module.
 *
 * Uses real temp directories and keyring's `InMemoryStorage`/`StandardTier`
 * (via a mocked `@de-otio/keyring`) to avoid touching the real OS
 * keychain or requiring the `@napi-rs/keyring` native binary in CI.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Track keyring invocations.
const mockSetup = vi.fn().mockResolvedValue(undefined);
const mockGet = vi.fn().mockResolvedValue(null);
const mockPut = vi.fn().mockResolvedValue(undefined);

// Stubs for keyring constructors. We treat the `@napi-rs/keyring`-backed
// `OsKeychainStorage` as a plain in-memory slot map that surfaces through
// the same spy.
vi.mock('@de-otio/keyring', () => {
  class OsKeychainUnavailable extends Error {
    constructor(msg: string) {
      super(msg);
      this.name = 'OsKeychainUnavailable';
    }
  }
  class KeyRing {
    constructor(_opts: unknown) {}
    setup = mockSetup;
    getWrapped = vi.fn().mockResolvedValue(null);
    unlockWithSshKey = vi.fn().mockResolvedValue(undefined);
    lock = vi.fn().mockResolvedValue(undefined);
    delete = vi.fn().mockResolvedValue(undefined);
    get isUnlocked() { return false; }
  }
  const StandardTier = { fromSshKey: vi.fn(() => ({ kind: 'standard' })) };
  class OsKeychainStorage {
    readonly platform = 'node' as const;
    readonly acceptedTiers: readonly string[];
    constructor(opts: { acceptedTiers?: readonly string[] }) {
      this.acceptedTiers = opts.acceptedTiers ?? ['standard', 'maximum'];
    }
    put = mockPut;
    get = mockGet;
    delete = vi.fn();
    list = vi.fn().mockResolvedValue([]);
  }
  class FileSystemStorage {
    readonly platform = 'node' as const;
    readonly acceptedTiers: readonly string[];
    constructor(opts: { acceptedTiers?: readonly string[] }) {
      this.acceptedTiers = opts.acceptedTiers ?? ['standard', 'maximum'];
    }
    put = mockPut;
    get = mockGet;
    delete = vi.fn();
    list = vi.fn().mockResolvedValue([]);
  }
  return {
    KeyRing,
    StandardTier,
    OsKeychainStorage,
    FileSystemStorage,
    OsKeychainUnavailable,
    parseSshPublicKey: vi.fn(() => ({
      type: 'ed25519',
      publicKeyBytes: new Uint8Array(32),
      fingerprint: 'SHA256:test',
    })),
    sshFingerprint: vi.fn(() => 'SHA256:test'),
  };
});

const mockDbClose = vi.fn();
const mockDbManagerCloseAll = vi.fn();
vi.mock('../../storage/database-manager.js', () => ({
  DatabaseManager: class {
    constructor() {
      /* no-op */
    }
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
    stderrWriteSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    // CHAOSKB_SYNC=off so we don't try to detect real SSH keys from ~/.ssh
    // or hit the network during tests.
    process.env.CHAOSKB_SYNC = 'off';
  });

  afterEach(() => {
    stderrWriteSpy.mockRestore();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.CHAOSKB_SYNC;
    delete process.env.CHAOSKB_KEY_STORAGE;
  });

  it('should create directory structure and write config when CHAOSKB_SYNC=off', async () => {
    // With CHAOSKB_SYNC=off, no SSH key is detected and no keyring
    // wrapping happens. CHAOSKB_KEY_STORAGE=file also drives the
    // file-based master.key fallback path so bootstrap can complete
    // without an SSH key.
    process.env.CHAOSKB_KEY_STORAGE = 'file';

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

    // Should not have attempted to wrap or init DB
    expect(mockSetup).not.toHaveBeenCalled();
    expect(mockDbClose).not.toHaveBeenCalled();
  });

  it('should fall back to file-based key when CHAOSKB_KEY_STORAGE=file is set and no SSH key', async () => {
    process.env.CHAOSKB_KEY_STORAGE = 'file';

    await bootstrap({ baseDir: chaoskbDir });

    // File-based key written
    const keyPath = path.join(chaoskbDir, 'master.key');
    expect(fs.existsSync(keyPath)).toBe(true);
    const keyHex = fs.readFileSync(keyPath, 'utf-8');
    expect(keyHex).toMatch(/^[0-9a-f]{64}$/);

    if (process.platform !== 'win32') {
      const keyStat = fs.statSync(keyPath);
      expect(keyStat.mode & 0o777).toBe(0o600);
    }

    // Config still written
    expect(fs.existsSync(path.join(chaoskbDir, 'config.json'))).toBe(true);
  });

  it('should throw when no SSH key is available and CHAOSKB_KEY_STORAGE not set', async () => {
    // CHAOSKB_SYNC=off + no CHAOSKB_KEY_STORAGE and no SSH key =>
    // bootstrap fails with a descriptive error.
    await expect(bootstrap({ baseDir: chaoskbDir })).rejects.toThrow(
      /No SSH key found|CHAOSKB_KEY_STORAGE=file/,
    );

    // Config should NOT have been written (bootstrap failed)
    expect(fs.existsSync(path.join(chaoskbDir, 'config.json'))).toBe(false);
  });

  it('should handle double-check pattern after lock acquisition', async () => {
    process.env.CHAOSKB_KEY_STORAGE = 'file';
    fs.mkdirSync(chaoskbDir, { recursive: true });

    // First call creates config
    await bootstrap({ baseDir: chaoskbDir });
    expect(mockDbClose).toHaveBeenCalled();

    vi.clearAllMocks();

    // Second call should no-op (idempotent)
    await bootstrap({ baseDir: chaoskbDir });
    expect(mockDbClose).not.toHaveBeenCalled();
  });
});
