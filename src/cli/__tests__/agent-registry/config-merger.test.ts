import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fs from 'node:fs';

vi.mock('node:fs');
vi.mock('../../agent-registry/path-validator.js', () => ({
  validateConfigPath: vi.fn(),
}));

// Helper: expected chaoskb entry shape.
// command is always the absolute node binary; args[0] is the MCP script path.
function expectedChaoskbEntry(extraArgs: string[] = []) {
  return {
    command: process.execPath,
    args: expect.arrayContaining([
      expect.stringMatching(/index\.js$/),
      ...extraArgs,
    ]),
  };
}

import { mergeAgentConfig, removeAgentConfig } from '../../agent-registry/config-merger.js';

describe('config merger', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should merge into existing config with other MCP servers', async () => {
    const existingConfig = {
      mcpServers: {
        other: { command: 'other-mcp', args: [] },
      },
    };

    vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(existingConfig));
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

    await mergeAgentConfig('/Users/test/.cursor/mcp.json');

    const writeCall = vi.mocked(fs.writeFileSync).mock.calls[0];
    const written = JSON.parse(writeCall[1] as string);

    expect(written.mcpServers.other).toEqual({ command: 'other-mcp', args: [] });
    expect(written.mcpServers.chaoskb).toMatchObject(expectedChaoskbEntry());
  });

  it('should create new config when file does not exist', async () => {
    vi.mocked(fs.readFileSync).mockImplementation(() => {
      const err = new Error('ENOENT') as NodeJS.ErrnoException;
      err.code = 'ENOENT';
      throw err;
    });
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.mkdirSync).mockReturnValue(undefined);
    vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

    await mergeAgentConfig('/Users/test/.cursor/mcp.json');

    const writeCall = vi.mocked(fs.writeFileSync).mock.calls[0];
    const written = JSON.parse(writeCall[1] as string);

    expect(written.mcpServers.chaoskb).toMatchObject(expectedChaoskbEntry());
  });

  it('should update existing chaoskb entry', async () => {
    const existingConfig = {
      mcpServers: {
        chaoskb: { command: 'old-chaoskb', args: ['--old'] },
        other: { command: 'other-mcp', args: [] },
      },
    };

    vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(existingConfig));
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

    await mergeAgentConfig('/Users/test/.cursor/mcp.json', ['--project', 'work']);

    const writeCall = vi.mocked(fs.writeFileSync).mock.calls[0];
    const written = JSON.parse(writeCall[1] as string);

    expect(written.mcpServers.chaoskb).toMatchObject(expectedChaoskbEntry(['--project', 'work']));
    // Other servers preserved
    expect(written.mcpServers.other).toEqual({ command: 'other-mcp', args: [] });
  });

  it('should preserve all other entries when removing chaoskb', async () => {
    const existingConfig = {
      mcpServers: {
        chaoskb: { command: 'chaoskb-mcp', args: [] },
        other: { command: 'other-mcp', args: [] },
      },
      customSetting: true,
    };

    vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(existingConfig));
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

    await removeAgentConfig('/Users/test/.cursor/mcp.json');

    const writeCall = vi.mocked(fs.writeFileSync).mock.calls[0];
    const written = JSON.parse(writeCall[1] as string);

    expect(written.mcpServers.chaoskb).toBeUndefined();
    expect(written.mcpServers.other).toEqual({ command: 'other-mcp', args: [] });
    expect(written.customSetting).toBe(true);
  });

  it('should handle malformed JSON gracefully', async () => {
    vi.mocked(fs.readFileSync).mockReturnValue('not valid json {{{');
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.writeFileSync).mockReturnValue(undefined);
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    await mergeAgentConfig('/Users/test/.cursor/mcp.json');

    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining('malformed JSON'),
    );

    const writeCall = vi.mocked(fs.writeFileSync).mock.calls[0];
    const written = JSON.parse(writeCall[1] as string);

    expect(written.mcpServers.chaoskb).toMatchObject(expectedChaoskbEntry());
  });

  it('should write config with 0o600 permissions', async () => {
    vi.mocked(fs.readFileSync).mockImplementation(() => {
      const err = new Error('ENOENT') as NodeJS.ErrnoException;
      err.code = 'ENOENT';
      throw err;
    });
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

    await mergeAgentConfig('/Users/test/.cursor/mcp.json');

    expect(fs.writeFileSync).toHaveBeenCalledWith(
      expect.any(String),
      expect.any(String),
      { mode: 0o600 },
    );
  });
});
