import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Mock dependencies
vi.mock('node:fs');
vi.mock('node:readline', () => ({
  createInterface: vi.fn(() => ({
    question: vi.fn(),
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
import { loadConfig } from '../../commands/setup.js';

describe('config upgrade-tier', () => {
  let originalExitCode: number | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    originalExitCode = process.exitCode;
    process.exitCode = undefined;
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    process.exitCode = originalExitCode;
    vi.restoreAllMocks();
  });

  it('should reject invalid tier argument', async () => {
    await upgradeTierCommand('invalid');
    expect(process.exitCode).toBe(1);
    expect(console.error).toHaveBeenCalledWith(
      expect.stringContaining('Invalid tier'),
    );
  });

  it('should error when not configured', async () => {
    vi.mocked(loadConfig).mockResolvedValue(null);

    await upgradeTierCommand('enhanced');
    expect(process.exitCode).toBe(1);
    expect(console.error).toHaveBeenCalledWith(
      expect.stringContaining('not configured'),
    );
  });

  it('should error when already at requested tier', async () => {
    vi.mocked(loadConfig).mockResolvedValue({
      securityTier: 'enhanced',
      projects: [],
    });

    await upgradeTierCommand('enhanced');
    expect(process.exitCode).toBe(1);
    expect(console.error).toHaveBeenCalledWith(
      expect.stringContaining('Already at'),
    );
  });

  it('should error when already at higher tier', async () => {
    vi.mocked(loadConfig).mockResolvedValue({
      securityTier: 'maximum',
      projects: [],
    });

    await upgradeTierCommand('enhanced');
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

    // KeyringService.retrieve returns null (mocked above)
    await upgradeTierCommand('enhanced');
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

    // Temporarily set stdin.isTTY to false
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
