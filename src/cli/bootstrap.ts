import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { acquireBootstrapLock } from './bootstrap-lock.js';

export const CHAOSKB_DIR = path.join(os.homedir(), '.chaoskb');
export const FILE_KEY_PATH = path.join(CHAOSKB_DIR, 'master.key');

export interface BootstrapOptions {
  /** Override the base directory (default: ~/.chaoskb). For testing. */
  baseDir?: string;
}

function resolveDir(baseDir?: string): string {
  return baseDir ?? CHAOSKB_DIR;
}

/**
 * Auto-bootstrap ChaosKB on first launch.
 *
 * Creates ~/.chaoskb/, generates a master key, stores it in the OS keyring,
 * initializes the database, and writes config.json — all with standard
 * security tier and no interactive prompts.
 *
 * Idempotent: no-ops if config.json already exists.
 * Concurrency-safe: uses file-based locking to prevent races.
 */
export async function bootstrap(options?: BootstrapOptions): Promise<void> {
  const chaoskbDir = resolveDir(options?.baseDir);
  const configPath = path.join(chaoskbDir, 'config.json');
  const modelsDir = path.join(chaoskbDir, 'models');
  const fileKeyPath = path.join(chaoskbDir, 'master.key');

  // Fast path: already configured
  if (fs.existsSync(configPath)) {
    return;
  }

  const releaseLock = await acquireBootstrapLock(chaoskbDir);
  try {
    // Double-check after acquiring lock — another process may have completed bootstrap
    if (fs.existsSync(configPath)) {
      return;
    }

    // 1. Create directory structure
    if (!fs.existsSync(chaoskbDir)) {
      fs.mkdirSync(chaoskbDir, { recursive: true, mode: 0o700 });
    }
    fs.chmodSync(chaoskbDir, 0o700);

    if (!fs.existsSync(modelsDir)) {
      fs.mkdirSync(modelsDir, { recursive: true, mode: 0o700 });
    }

    // 2. Generate master key
    const { EncryptionService } = await import('../crypto/encryption-service.js');
    const encryption = new EncryptionService();
    const masterKey = encryption.generateMasterKey();

    // 3. Store master key
    try {
      await storeKeyInKeyring(masterKey);
    } catch (keyringError) {
      // Keyring failed — check for file-based fallback
      if (process.env.CHAOSKB_KEY_STORAGE === 'file') {
        process.stderr.write(
          '\n⚠ OS keyring unavailable. Storing key in ' + fileKeyPath + ' (file-based).\n' +
          '  This is less secure than the OS keyring. The key file is readable by any process running as your user.\n\n',
        );
        fs.writeFileSync(fileKeyPath, masterKey.buffer.toString('hex'), { mode: 0o600 });
      } else {
        masterKey.dispose();
        throw new Error(
          `Failed to store master key in OS keyring: ${keyringError instanceof Error ? keyringError.message : String(keyringError)}\n\n` +
          '  To fix this, either:\n' +
          '  • Install/configure your OS keyring service (macOS Keychain, Linux Secret Service, Windows Credential Manager)\n' +
          '  • Set CHAOSKB_KEY_STORAGE=file to use file-based key storage (less secure)\n',
        );
      }
    }

    masterKey.dispose();

    // 4. Initialize database
    const { DatabaseManager } = await import('../storage/database-manager.js');
    const dbManager = new DatabaseManager(chaoskbDir);
    const db = dbManager.getPersonalDb();
    db.close();
    dbManager.closeAll();

    // 5. Write config
    const config = {
      securityTier: 'standard',
      projects: [],
    };
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
  } finally {
    releaseLock();
  }
}

async function storeKeyInKeyring(masterKey: { buffer: Buffer }): Promise<void> {
  // macOS: warn about potential keychain access dialog
  if (process.platform === 'darwin') {
    process.stderr.write(
      'Storing encryption key in macOS Keychain.\n' +
      'You may see a system dialog asking to allow keychain access — this is expected.\n',
    );
  }

  const { KeyringService } = await import('../crypto/keyring.js');
  const keyring = new KeyringService();
  await keyring.store('chaoskb', 'master-key', masterKey as import('../crypto/types.js').ISecureBuffer);
}
