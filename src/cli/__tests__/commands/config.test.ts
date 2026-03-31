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

const mockRetrieve = vi.fn().mockResolvedValue(null);
const mockDelete = vi.fn().mockResolvedValue(true);

vi.mock('../../../crypto/keyring.js', () => ({
  KeyringService: class {
    retrieve = mockRetrieve;
    store = vi.fn().mockResolvedValue(undefined);
    delete = mockDelete;
  },
}));
vi.mock('../../bootstrap.js', () => ({
  FILE_KEY_PATH: path.join(os.homedir(), '.chaoskb', 'master.key'),
  CHAOSKB_DIR: path.join(os.homedir(), '.chaoskb'),
}));

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
  });

  afterEach(() => {
    process.exitCode = originalExitCode;
    vi.restoreAllMocks();
  });

  describe('validation', () => {
    it('should reject invalid tier argument', async () => {
      await upgradeTierCommand('invalid');
      expect(process.exitCode).toBe(1);
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('Invalid tier'),
      );
    });

    it('should reject deprecated enhanced tier', async () => {
      await upgradeTierCommand('enhanced');
      expect(process.exitCode).toBe(1);
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('deprecated'),
      );
    });

    it('should error when not configured', async () => {
      vi.mocked(loadConfig).mockResolvedValue(null);

      await upgradeTierCommand('maximum');
      expect(process.exitCode).toBe(1);
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('not configured'),
      );
    });

    it('should error when already at requested tier', async () => {
      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'maximum',
        projects: [],
      });

      await upgradeTierCommand('maximum');
      expect(process.exitCode).toBe(1);
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('Already at'),
      );
    });

    it('should error when master key not found', async () => {
      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'standard',
        projects: [],
      });

      await upgradeTierCommand('maximum');
      expect(process.exitCode).toBe(1);
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('Master key not found'),
      );
    });

    it('should error for maximum tier when stdin is not TTY', async () => {
      const mockMasterKey = {
        buffer: Buffer.alloc(32, 0xaa),
        length: 32,
        isDisposed: false,
        dispose: vi.fn(),
      };
      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'standard',
        projects: [],
      });
      mockRetrieve.mockResolvedValueOnce(mockMasterKey);

      const originalIsTTY = process.stdin.isTTY;
      Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });

      try {
        await upgradeTierCommand('maximum');
        expect(process.exitCode).toBe(1);
        expect(console.error).toHaveBeenCalledWith(
          expect.stringContaining('interactive terminal'),
        );
      } finally {
        Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, configurable: true });
      }
    });
  });

  describe('upgrade to maximum (happy path)', () => {
    it('should encrypt key, write blob, remove from keyring, and update config', async () => {
      const keyBytes = Buffer.alloc(32);
      for (let i = 0; i < 32; i++) keyBytes[i] = i;
      const mockMasterKey = {
        buffer: keyBytes,
        length: 32,
        isDisposed: false,
        dispose: vi.fn(),
      };

      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'standard',
        projects: [],
      });
      mockRetrieve.mockResolvedValueOnce(mockMasterKey);

      const originalIsTTY = process.stdin.isTTY;
      Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });

      // Passphrase must be >= 25 characters
      const passphrase = 'correct horse battery staple!';
      mockAnswers = [passphrase, passphrase]; // enter + confirm

      // Mock fs.writeFileSync to capture the blob
      let writtenBlob: string | undefined;
      vi.mocked(fs.writeFileSync).mockImplementation((_path, data) => {
        writtenBlob = data as string;
      });
      vi.mocked(fs.unlinkSync).mockImplementation(() => {});

      try {
        await upgradeTierCommand('maximum');

        expect(process.exitCode).toBeUndefined();

        // Verify blob was written
        expect(fs.writeFileSync).toHaveBeenCalledWith(
          expect.stringContaining('master-key.enc'),
          expect.any(String),
          { mode: 0o600 },
        );

        // Verify blob structure
        expect(writtenBlob).toBeDefined();
        const blob = JSON.parse(writtenBlob!);
        expect(blob.v).toBe(1);
        expect(blob.kdf).toBe('argon2id');
        expect(blob.t).toBe(3);
        expect(blob.m).toBe(65536);
        expect(blob.p).toBe(1);
        expect(blob.salt).toMatch(/^[0-9a-f]+$/);
        expect(blob.nonce).toMatch(/^[0-9a-f]+$/);
        expect(blob.ciphertext).toMatch(/^[0-9a-f]+$/);

        // Verify keyring entry was deleted
        expect(mockDelete).toHaveBeenCalledWith('chaoskb', 'master-key');

        // Verify config updated
        expect(saveConfig).toHaveBeenCalledWith(
          expect.objectContaining({ securityTier: 'maximum' }),
        );

        expect(mockMasterKey.dispose).toHaveBeenCalled();
      } finally {
        Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, configurable: true });
      }
    });

    it('should reject passphrase shorter than 25 characters', async () => {
      const mockMasterKey = {
        buffer: Buffer.alloc(32, 0xaa),
        length: 32,
        isDisposed: false,
        dispose: vi.fn(),
      };
      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'standard',
        projects: [],
      });
      mockRetrieve.mockResolvedValueOnce(mockMasterKey);

      const originalIsTTY = process.stdin.isTTY;
      Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });

      mockAnswers = ['tooshort']; // < 25 chars

      try {
        await upgradeTierCommand('maximum');
        expect(process.exitCode).toBe(1);
        expect(console.error).toHaveBeenCalledWith(
          expect.stringContaining('25 characters'),
        );
      } finally {
        Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, configurable: true });
      }
    });

    it('should reject mismatched passphrases', async () => {
      const mockMasterKey = {
        buffer: Buffer.alloc(32, 0xaa),
        length: 32,
        isDisposed: false,
        dispose: vi.fn(),
      };
      vi.mocked(loadConfig).mockResolvedValue({
        securityTier: 'standard',
        projects: [],
      });
      mockRetrieve.mockResolvedValueOnce(mockMasterKey);

      const originalIsTTY = process.stdin.isTTY;
      Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });

      mockAnswers = ['correct horse battery staple!', 'different horse battery staple!'];

      try {
        await upgradeTierCommand('maximum');
        expect(process.exitCode).toBe(1);
        expect(console.error).toHaveBeenCalledWith(
          expect.stringContaining('do not match'),
        );
      } finally {
        Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, configurable: true });
      }
    });
  });
});
