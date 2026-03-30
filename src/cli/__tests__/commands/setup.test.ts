import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Mock fs before importing the module
vi.mock('node:fs');

describe('setup command', () => {
  const homeDir = os.homedir();
  const chaoskbDir = path.join(homeDir, '.chaoskb');
  const configPath = path.join(chaoskbDir, 'config.json');

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('loadConfig', () => {
    it('should return null when config does not exist', async () => {
      vi.mocked(fs.readFileSync).mockImplementation(() => {
        throw new Error('ENOENT');
      });

      const { loadConfig } = await import('../../commands/setup.js');
      const config = await loadConfig();
      expect(config).toBeNull();
    });

    it('should return parsed config when file exists', async () => {
      const mockConfig = {
        securityTier: 'standard',
        projects: [],
      };
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));

      const { loadConfig } = await import('../../commands/setup.js');
      const config = await loadConfig();
      expect(config).toEqual(mockConfig);
    });
  });

  describe('saveConfig', () => {
    it('should create directory with 0o700 permissions', async () => {
      vi.mocked(fs.mkdirSync).mockReturnValue(undefined);
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      const { saveConfig } = await import('../../commands/setup.js');
      await saveConfig({ securityTier: 'standard', projects: [] });

      expect(fs.mkdirSync).toHaveBeenCalledWith(chaoskbDir, {
        recursive: true,
        mode: 0o700,
      });
    });

    it('should write config with 0o600 permissions', async () => {
      vi.mocked(fs.mkdirSync).mockReturnValue(undefined);
      vi.mocked(fs.writeFileSync).mockReturnValue(undefined);

      const { saveConfig } = await import('../../commands/setup.js');
      const config = { securityTier: 'standard', projects: [] };
      await saveConfig(config);

      expect(fs.writeFileSync).toHaveBeenCalledWith(
        configPath,
        JSON.stringify(config, null, 2),
        { mode: 0o600 },
      );
    });
  });

  describe('CHAOSKB_DIR', () => {
    it('should point to ~/.chaoskb', async () => {
      const { CHAOSKB_DIR } = await import('../../commands/setup.js');
      expect(CHAOSKB_DIR).toBe(chaoskbDir);
    });
  });

  describe('setupCommand', () => {
    it('should report already configured when config exists', async () => {
      const mockConfig = { securityTier: 'standard', projects: [] };
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(mockConfig));
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

      const { setupCommand } = await import('../../commands/setup.js');
      await setupCommand();

      expect(consoleSpy).toHaveBeenCalledWith('ChaosKB is already configured.');
      consoleSpy.mockRestore();
    });
  });
});
