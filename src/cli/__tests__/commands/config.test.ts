import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as path from 'node:path';
import * as os from 'node:os';
import * as fs from 'node:fs';

// Mock dependencies
vi.mock('node:fs');

// readline mock — answers are set per-test via mockAnswers
let mockAnswers: string[] = [];
let answerIndex = 0;
vi.mock('node:readline', () => ({
  createInterface: vi.fn(() => ({
    question: vi.fn((_q: string, cb: (answer: string) => void) => {
      cb(mockAnswers[answerIndex++] ?? '');
    }),
    close: vi.fn(),
  })),
}));

vi.mock('../../commands/setup.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../commands/setup.js')>();
  return {
    ...actual,
    loadConfig: vi.fn(),
    saveConfig: vi.fn(),
    CHAOSKB_DIR: path.join(os.homedir(), '.chaoskb'),
  };
});

// Mock keyring: StandardTier unlock + MaximumTier wrap. We return a
// synthetic WrappedKey structure on wrap so the config command can
// serialise it to the master-key.enc blob.
const mockUnlockWithSshKey = vi.fn().mockResolvedValue(undefined);
const mockWithMaster = vi.fn();
const mockLock = vi.fn().mockResolvedValue(undefined);
const mockDelete = vi.fn().mockResolvedValue(undefined);
const mockGet = vi.fn();
const mockMaxWrap = vi.fn();
const mockMaxUnwrap = vi.fn();

vi.mock('@de-otio/keyring', () => {
  class KeyRing {
    constructor(_opts: unknown) {}
    unlockWithSshKey = mockUnlockWithSshKey;
    withMaster = mockWithMaster;
    lock = mockLock;
    delete = mockDelete;
    getWrapped = vi.fn().mockResolvedValue(null);
  }
  const StandardTier = { fromSshKey: vi.fn(() => ({ kind: 'standard' })) };
  class MaximumTier {
    static fromPassphrase = vi.fn((passphrase: string) => {
      if (!passphrase) throw new Error('passphrase required');
      return {
        kind: 'maximum',
        wrap: mockMaxWrap,
        unwrap: mockMaxUnwrap,
      };
    });
  }
  class OsKeychainStorage {
    readonly platform = 'node' as const;
    readonly acceptedTiers: readonly string[];
    constructor(opts: { acceptedTiers?: readonly string[] }) {
      this.acceptedTiers = opts.acceptedTiers ?? ['standard', 'maximum'];
    }
    get = mockGet;
    put = vi.fn().mockResolvedValue(undefined);
    delete = vi.fn();
    list = vi.fn().mockResolvedValue([]);
  }
  class FileSystemStorage {
    readonly platform = 'node' as const;
    readonly acceptedTiers: readonly string[];
    constructor(opts: { acceptedTiers?: readonly string[] }) {
      this.acceptedTiers = opts.acceptedTiers ?? ['standard', 'maximum'];
    }
    get = mockGet;
    put = vi.fn().mockResolvedValue(undefined);
    delete = vi.fn();
    list = vi.fn().mockResolvedValue([]);
  }
  return {
    KeyRing,
    StandardTier,
    MaximumTier,
    OsKeychainStorage,
    FileSystemStorage,
  };
});

import { upgradeTierCommand } from '../../commands/config.js';
import { loadConfig, saveConfig } from '../../commands/setup.js';

describe('config upgrade-tier', () => {
  let originalExitCode: number | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    originalExitCode = process.exitCode;
    process.exitCode = undefined;
    mockAnswers = [];
    answerIndex = 0;
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
    // fs.existsSync default: true (simulate that SSH key and config are present)
    vi.mocked(fs.existsSync).mockReturnValue(true);
    // Stub read of SSH pubkey + privkey + any other file reads with plausible defaults
    vi.mocked(fs.readFileSync).mockImplementation(((p: string) => {
      if (String(p).endsWith('.pub')) {
        return 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1lc3NhZ2U= test@host';
      }
      return '-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n';
    }) as typeof fs.readFileSync);
    // Default: keyring slot has an existing wrapped blob
    mockGet.mockResolvedValue({
      v: 1,
      tier: 'standard',
      envelope: new Uint8Array(16),
      ts: '2026-01-01T00:00:00.000Z',
    });
    // Default: withMaster invokes callback with a stand-in master that
    // supports .dispose() and .buffer access.
    mockWithMaster.mockImplementation(async (fn: (m: unknown) => Promise<unknown>) =>
      fn({ buffer: Buffer.alloc(32, 0xab), length: 32, dispose: vi.fn() }),
    );
    // Default: MaximumTier.wrap produces a serialisable WrappedKey.
    mockMaxWrap.mockResolvedValue({
      v: 1,
      tier: 'maximum',
      envelope: new Uint8Array([1, 2, 3, 4]),
      kdfParams: {
        algorithm: 'argon2id',
        t: 3,
        m: 65536,
        p: 1,
        salt: new Uint8Array(16),
      },
      ts: '2026-01-01T00:00:00.000Z',
    });
    // Default: MaximumTier.unwrap (used by verify-after-write) succeeds.
    mockMaxUnwrap.mockResolvedValue({ buffer: Buffer.alloc(32, 0xcc), dispose: vi.fn() });
  });

  afterEach(() => {
    process.exitCode = originalExitCode;
    vi.restoreAllMocks();
  });

  describe('validation', () => {
    it('should reject invalid tier argument', async () => {
      await upgradeTierCommand('invalid');
      expect(process.exitCode).toBe(1);
      expect(console.error).toHaveBeenCalledWith(expect.stringContaining('Invalid tier'));
    });

    it('should reject deprecated enhanced tier', async () => {
      await upgradeTierCommand('enhanced');
      expect(process.exitCode).toBe(1);
      expect(console.error).toHaveBeenCalledWith(expect.stringContaining('deprecated'));
    });

    it('should error when not configured', async () => {
      vi.mocked(loadConfig).mockResolvedValue(null);

      await upgradeTierCommand('maximum');
      expect(process.exitCode).toBe(1);
      expect(console.error).toHaveBeenCalledWith(expect.stringContaining('not configured'));
    });

    it('should error when already at requested tier', async () => {
      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'maximum',
        projects: [],
      });

      await upgradeTierCommand('maximum');
      expect(process.exitCode).toBe(1);
      expect(console.error).toHaveBeenCalledWith(expect.stringContaining('Already at'));
    });

    it('should error when master key not found (empty keyring slot)', async () => {
      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'standard',
        projects: [],
      });
      mockGet.mockResolvedValueOnce(null);

      await upgradeTierCommand('maximum');
      expect(process.exitCode).toBe(1);
      expect(console.error).toHaveBeenCalledWith(expect.stringContaining('Master key not found'));
    });

    it('should error for maximum tier when stdin is not TTY', async () => {
      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'standard',
        projects: [],
      });

      const originalIsTTY = process.stdin.isTTY;
      Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });

      try {
        await upgradeTierCommand('maximum');
        expect(process.exitCode).toBe(1);
        expect(console.error).toHaveBeenCalledWith(expect.stringContaining('interactive terminal'));
      } finally {
        Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, configurable: true });
      }
    });
  });

  describe('upgrade to maximum (happy path)', () => {
    it('should wrap under MaximumTier, write blob, and update config', async () => {
      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'standard',
        projects: [],
      });

      const originalIsTTY = process.stdin.isTTY;
      Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });

      const passphrase = 'correct horse battery staple!';
      mockAnswers = [passphrase, passphrase];

      let writtenBlob: string | undefined;
      vi.mocked(fs.writeFileSync).mockImplementation((_p, data) => {
        writtenBlob = data as string;
      });
      vi.mocked(fs.unlinkSync).mockImplementation(() => {});

      // After writeFileSync captures the blob, verifyRoundTrip reads the
      // same blob back. Route readFileSync for master-key.enc to the
      // captured value; other reads continue to return SSH key text.
      vi.mocked(fs.readFileSync).mockImplementation(((p: string) => {
        const ps = String(p);
        if (ps.endsWith('master-key.enc')) return writtenBlob ?? '{}';
        if (ps.endsWith('.pub')) {
          return 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1lc3NhZ2U= test@host';
        }
        return '-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n';
      }) as typeof fs.readFileSync);

      try {
        await upgradeTierCommand('maximum');

        expect(process.exitCode).toBeUndefined();

        // Verify blob was written
        expect(fs.writeFileSync).toHaveBeenCalledWith(
          expect.stringContaining('master-key.enc'),
          expect.any(String),
          { mode: 0o600 },
        );

        // Verify blob structure (the serialised WrappedKey shape)
        expect(writtenBlob).toBeDefined();
        const blob = JSON.parse(writtenBlob!);
        expect(blob.v).toBe(1);
        expect(blob.tier).toBe('maximum');
        expect(typeof blob.envelope).toBe('string');
        expect(blob.kdfParams.algorithm).toBe('argon2id');
        expect(blob.kdfParams.t).toBe(3);
        expect(blob.kdfParams.m).toBe(65536);
        expect(blob.kdfParams.p).toBe(1);

        // Verify keyring Standard entry was deleted
        expect(mockDelete).toHaveBeenCalled();

        // Verify config updated
        expect(saveConfig).toHaveBeenCalledWith(
          expect.objectContaining({ securityTier: 'maximum' }),
        );
      } finally {
        Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, configurable: true });
      }
    });

    it('should reject passphrase shorter than 25 characters', async () => {
      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'standard',
        projects: [],
      });

      const originalIsTTY = process.stdin.isTTY;
      Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });

      mockAnswers = ['tooshort'];

      try {
        await upgradeTierCommand('maximum');
        expect(process.exitCode).toBe(1);
        expect(console.error).toHaveBeenCalledWith(expect.stringContaining('25 characters'));
      } finally {
        Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, configurable: true });
      }
    });

    it('should reject mismatched passphrases', async () => {
      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'standard',
        projects: [],
      });

      const originalIsTTY = process.stdin.isTTY;
      Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });

      mockAnswers = ['correct horse battery staple!', 'different horse battery staple!'];

      try {
        await upgradeTierCommand('maximum');
        expect(process.exitCode).toBe(1);
        expect(console.error).toHaveBeenCalledWith(expect.stringContaining('do not match'));
      } finally {
        Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, configurable: true });
      }
    });
  });
});
