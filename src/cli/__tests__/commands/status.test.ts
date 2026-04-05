import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fs from 'node:fs';

vi.mock('node:fs');
vi.mock('../../commands/setup.js', () => ({
  loadConfig: vi.fn(),
  CHAOSKB_DIR: '/Users/test/.chaoskb',
}));
vi.mock('../../agent-registry/detector.js', () => ({
  detectAgents: vi.fn().mockResolvedValue([]),
}));

import { statusCommand } from '../../commands/status.js';
import { loadConfig } from '../../commands/setup.js';

describe('status command', () => {
  let consoleOutput: string[];

  beforeEach(() => {
    vi.clearAllMocks();
    consoleOutput = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      consoleOutput.push(args.join(' '));
    });
  });

  it('should show "not initialized" when no config exists', async () => {
    vi.mocked(loadConfig).mockResolvedValue(null);

    await statusCommand({});

    expect(consoleOutput.some((l) => l.includes('not initialized'))).toBe(true);
  });

  it('should display security tier', async () => {
    vi.mocked(loadConfig).mockResolvedValue({
      securityTier: 'standard',
      projects: [],
    });
    vi.mocked(fs.existsSync).mockReturnValue(false);

    await statusCommand({});

    expect(consoleOutput.some((l) => l.includes('standard'))).toBe(true);
  });

  it('should display sync endpoint when configured', async () => {
    vi.mocked(loadConfig).mockResolvedValue({
      securityTier: 'standard',
      endpoint: 'https://api.chaoskb.com',
      projects: [],
    });
    vi.mocked(fs.existsSync).mockReturnValue(false);

    await statusCommand({});

    expect(
      consoleOutput.some((l) => l.includes('https://api.chaoskb.com')),
    ).toBe(true);
  });

  it('should show local-only when no endpoint configured', async () => {
    vi.mocked(loadConfig).mockResolvedValue({
      securityTier: 'enhanced',
      projects: [],
    });
    vi.mocked(fs.existsSync).mockReturnValue(false);

    await statusCommand({});

    expect(consoleOutput.some((l) => l.includes('local-only'))).toBe(true);
  });

  it('should list project KBs', async () => {
    vi.mocked(loadConfig).mockResolvedValue({
      securityTier: 'standard',
      projects: [
        { name: 'work', createdAt: '2026-03-01T00:00:00Z' },
        { name: 'personal', createdAt: '2026-03-10T00:00:00Z' },
      ],
    });
    vi.mocked(fs.existsSync).mockReturnValue(false);

    await statusCommand({});

    expect(consoleOutput.some((l) => l.includes('work'))).toBe(true);
    expect(consoleOutput.some((l) => l.includes('personal'))).toBe(true);
  });
});
