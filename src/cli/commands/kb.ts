import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const CHAOSKB_DIR = path.join(os.homedir(), '.chaoskb');

export interface KBConfig {
  name: string;
  sshKeyPath?: string;
  github?: string;
  endpoint?: string;
  securityTier?: string;
  createdAt: string;
}

/**
 * F1.1: `chaoskb kb create <name> --key <path> [--github <username>]`
 */
export async function kbCreateCommand(
  name: string,
  options: { key?: string; github?: string },
): Promise<void> {
  if (!isValidKBName(name)) {
    console.error('Invalid KB name. Use only alphanumeric characters, hyphens, and underscores.');
    process.exit(1);
  }

  const kbDir = path.join(CHAOSKB_DIR, name);
  if (fs.existsSync(kbDir)) {
    console.error(`KB "${name}" already exists at ${kbDir}`);
    process.exit(1);
  }

  // F1.2: Create directory structure
  fs.mkdirSync(path.join(kbDir, 'db'), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(kbDir, 'keys'), { recursive: true, mode: 0o700 });

  // F1.4: Generate an independent master key for encryption isolation
  const masterKey = crypto.randomBytes(32);
  fs.writeFileSync(
    path.join(kbDir, 'keys', 'master.key'),
    masterKey.toString('hex'),
    { mode: 0o600 },
  );
  masterKey.fill(0); // Zero out from memory

  const config: KBConfig = {
    name,
    sshKeyPath: options.key,
    github: options.github,
    createdAt: new Date().toISOString(),
  };

  // Write config
  fs.writeFileSync(
    path.join(kbDir, 'config.json'),
    JSON.stringify(config, null, 2),
    { mode: 0o600 },
  );

  console.log(`KB "${name}" created at ${kbDir}`);
  console.log('  Independent master key generated.');

  if (options.github) {
    console.log(`  GitHub: ${options.github}`);
  }
  if (options.key) {
    console.log(`  SSH key: ${options.key}`);
  }

  // F1.3: If an endpoint is configured, register this KB independently
  const mainConfigPath = path.join(CHAOSKB_DIR, 'config.json');
  if (fs.existsSync(mainConfigPath)) {
    try {
      const mainConfig = JSON.parse(fs.readFileSync(mainConfigPath, 'utf-8'));
      if (mainConfig.endpoint && options.key) {
        console.log(`  To sync this KB, run: chaoskb-mcp setup-sync --github ${options.github ?? '<username>'}`);
      }
    } catch {
      // Ignore config parse errors
    }
  }
}

/**
 * F1.5: `chaoskb kb list`
 */
export async function kbListCommand(): Promise<void> {
  const kbs = listKBs();

  if (kbs.length === 0) {
    console.log('No named KBs found.');
    console.log('Use `chaoskb kb create <name>` to create one.');
    return;
  }

  console.log('');
  console.log('  Knowledge Bases');
  console.log('  ===============');
  console.log('');

  for (const kb of kbs) {
    const keyInfo = kb.sshKeyPath ? ` (key: ${path.basename(kb.sshKeyPath)})` : '';
    const ghInfo = kb.github ? ` [GitHub: ${kb.github}]` : '';
    console.log(`  ${kb.name}${keyInfo}${ghInfo}`);
    console.log(`    Created: ${new Date(kb.createdAt).toLocaleDateString()}`);
    console.log('');
  }
}

/**
 * F1.6: `chaoskb kb delete <name>`
 */
export async function kbDeleteCommand(name: string): Promise<void> {
  const kbDir = path.join(CHAOSKB_DIR, name);

  if (!fs.existsSync(kbDir)) {
    console.error(`KB "${name}" not found.`);
    process.exit(1);
  }

  // Remove local data
  fs.rmSync(kbDir, { recursive: true });
  console.log(`KB "${name}" deleted.`);
}

/**
 * List all named KBs by reading config.json from each subdirectory.
 */
export function listKBs(): KBConfig[] {
  const kbs: KBConfig[] = [];

  try {
    const entries = fs.readdirSync(CHAOSKB_DIR, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const configPath = path.join(CHAOSKB_DIR, entry.name, 'config.json');
      try {
        const raw = fs.readFileSync(configPath, 'utf-8');
        const config = JSON.parse(raw) as KBConfig;
        kbs.push(config);
      } catch {
        // Not a KB directory, skip
      }
    }
  } catch {
    // ~/.chaoskb doesn't exist
  }

  return kbs;
}

/**
 * F1.7: Get the default KB path. Creates `~/.chaoskb/default/` if needed.
 */
export function getDefaultKBPath(): string {
  return path.join(CHAOSKB_DIR, 'default');
}

/**
 * F1.8: Migrate flat layout to `default/` subdirectory.
 *
 * If `~/.chaoskb/config.json` exists (flat layout), move everything
 * into `~/.chaoskb/default/`.
 */
export function migrateToNamedKBLayout(): boolean {
  const flatConfig = path.join(CHAOSKB_DIR, 'config.json');
  if (!fs.existsSync(flatConfig)) return false;

  const defaultDir = path.join(CHAOSKB_DIR, 'default');
  if (fs.existsSync(defaultDir)) return false; // Already migrated

  fs.mkdirSync(defaultDir, { recursive: true, mode: 0o700 });

  // Move config.json, local.db, and key files
  const filesToMove = ['config.json', 'local.db'];
  for (const file of filesToMove) {
    const src = path.join(CHAOSKB_DIR, file);
    const dest = path.join(defaultDir, file);
    if (fs.existsSync(src)) {
      fs.renameSync(src, dest);
    }
  }

  // Move key files if they exist
  const masterKeyFile = path.join(CHAOSKB_DIR, 'master.key');
  if (fs.existsSync(masterKeyFile)) {
    fs.mkdirSync(path.join(defaultDir, 'keys'), { recursive: true, mode: 0o700 });
    fs.renameSync(masterKeyFile, path.join(defaultDir, 'keys', 'master.key'));
  }

  return true;
}

/**
 * F3.1: Detect which named KBs can be synced on this device.
 *
 * For each named KB that has an SSH key configured, check if the
 * corresponding key exists on this device. Returns matching KB names.
 */
export function detectSyncableKBs(): { name: string; sshKeyPath: string; github?: string }[] {
  const kbs = listKBs();
  const syncable: { name: string; sshKeyPath: string; github?: string }[] = [];

  for (const kb of kbs) {
    if (!kb.sshKeyPath) continue;
    // Check if the private key or public key exists on this device
    if (fs.existsSync(kb.sshKeyPath) || fs.existsSync(kb.sshKeyPath + '.pub')) {
      syncable.push({ name: kb.name, sshKeyPath: kb.sshKeyPath, github: kb.github });
    }
  }

  return syncable;
}

function isValidKBName(name: string): boolean {
  return /^[a-zA-Z0-9_-]+$/.test(name) && name.length > 0 && name.length <= 64;
}
