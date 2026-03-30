import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { ChaosKBConfig } from '../mcp-server.js';

const CHAOSKB_DIR = path.join(os.homedir(), '.chaoskb');
const CONFIG_PATH = path.join(CHAOSKB_DIR, 'config.json');

export async function loadConfig(): Promise<ChaosKBConfig | null> {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
    return JSON.parse(raw) as ChaosKBConfig;
  } catch {
    return null;
  }
}

export async function saveConfig(config: ChaosKBConfig): Promise<void> {
  fs.mkdirSync(CHAOSKB_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), {
    mode: 0o600,
  });
}

/**
 * Setup command — now a thin alias for auto-bootstrap.
 * Kept for backwards compatibility with existing documentation and scripts.
 */
export async function setupCommand(): Promise<void> {
  const config = await loadConfig();
  if (config) {
    console.log('ChaosKB is already configured.');
    console.log(`  Config: ${CONFIG_PATH}`);
    console.log(`  Security tier: ${config.securityTier}`);
    return;
  }

  console.log('Setting up ChaosKB...');
  const { bootstrap } = await import('../bootstrap.js');
  await bootstrap();
  console.log('ChaosKB is ready.');
}

export { CHAOSKB_DIR, CONFIG_PATH };
