import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  KeyRing,
  StandardTier,
  OsKeychainStorage,
  FileSystemStorage,
  parseSshPublicKey,
  type KeyStorage,
} from '@de-otio/keyring';
import { loadConfig, saveConfig } from './setup.js';
import { KEYRING_SERVICE, CHAOSKB_DIR, FILE_KEY_PATH } from '../bootstrap.js';

/**
 * CLI command: chaoskb-mcp config rotate-key --new-key <path>
 *
 * Performs Phase 1 of two-phase key rotation:
 * 1. Reads current config to get endpoint and current key fingerprint
 * 2. Detects the new SSH key from --new-key path (or auto-detects)
 * 3. Unlocks the master key from the existing keyring using the old SSH key
 * 4. Re-wraps the master key with the new SSH public key (StandardTier wrap)
 * 5. Calls POST /v1/rotate-start with { newPublicKey, wrappedBlob }
 * 6. Uploads new wrapped blob to /v1/wrapped-key
 * 7. Updates local keyring storage with the new wrapping and updates config
 */
export async function rotateKeyCommand(
  newKeyPath?: string,
  options?: { dryRun?: boolean },
): Promise<void> {
  const dryRun = options?.dryRun ?? false;
  const config = await loadConfig();
  if (!config) {
    console.error('ChaosKB is not configured. Run `chaoskb-mcp setup` first.');
    process.exitCode = 1;
    return;
  }

  if (!config.endpoint) {
    console.error('Sync is not configured. Key rotation requires an active sync endpoint.');
    process.exitCode = 1;
    return;
  }

  if (!config.sshKeyFingerprint) {
    console.error('No SSH key configured. Run `chaoskb-mcp setup-sync` first.');
    process.exitCode = 1;
    return;
  }

  // Detect the new SSH key
  const newKeyInfo = await detectNewSSHKey(newKeyPath);
  if (!newKeyInfo) {
    console.error(
      'Could not detect a new SSH key.' +
        (newKeyPath ? ` File not found: ${newKeyPath}` : ' Specify --new-key <path>.'),
    );
    process.exitCode = 1;
    return;
  }

  // Verify the new key is different from the current one
  if (newKeyInfo.fingerprint === config.sshKeyFingerprint) {
    console.error('The new key is the same as the current key. Nothing to rotate.');
    process.exitCode = 1;
    return;
  }

  if (dryRun) {
    console.log('[dry-run] Would rotate SSH key for sync.');
    console.log('[dry-run]   Current key: %s', config.sshKeyFingerprint);
    console.log('[dry-run]   New key:     %s', newKeyInfo.fingerprint);
    console.log('[dry-run] This will:');
    console.log('[dry-run]   - Re-wrap the master key with the new SSH public key');
    console.log('[dry-run]   - Call POST /v1/rotate-start on the sync server');
    console.log('[dry-run]   - Upload new wrapped key blob to /v1/wrapped-key');
    console.log('[dry-run]   - Update config with new key fingerprint');
    console.log('[dry-run] No changes made.');
    return;
  }

  // Resolve the OLD SSH key PEM. Preference: config.sshKeyPath; fall back
  // to ~/.ssh/id_ed25519 then ~/.ssh/id_rsa.
  const oldKeyPath = resolveOldKeyPath(config.sshKeyPath);
  if (!oldKeyPath) {
    console.error(
      'Could not locate the previous SSH private key. Set CHAOSKB_SYNC=off or reconfigure sync.',
    );
    process.exitCode = 1;
    return;
  }

  let oldKeyPem: string;
  try {
    oldKeyPem = fs.readFileSync(oldKeyPath, 'utf-8');
  } catch (err) {
    console.error(`Failed to read old SSH private key at ${oldKeyPath}: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
    return;
  }

  // Read the old public key line so we can reconstruct the StandardTier.
  let oldPublicKeyLine: string;
  try {
    oldPublicKeyLine = fs.readFileSync(`${oldKeyPath}.pub`, 'utf-8').trim();
  } catch {
    console.error(`Failed to read old SSH public key at ${oldKeyPath}.pub`);
    process.exitCode = 1;
    return;
  }

  // Build the storage backend. Supports the filesystem fallback when
  // CHAOSKB_KEY_STORAGE=file is set.
  const storage = buildStorage();

  // Unlock the keyring with the old SSH key.
  const oldTier = StandardTier.fromSshKey(oldPublicKeyLine);
  const ring = new KeyRing({ tier: oldTier, storage });
  try {
    await ring.unlockWithSshKey(oldKeyPem);
  } catch (err) {
    // Check for legacy file-based master-key fallback when the keyring
    // slot is empty (pre-migration users).
    if (process.env.CHAOSKB_KEY_STORAGE === 'file' && fs.existsSync(FILE_KEY_PATH)) {
      console.error(
        'Legacy master.key file found but keyring slot is empty. Re-run setup or migrate by hand.',
      );
    } else {
      console.error(
        `Failed to unlock master key with old SSH key: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    process.exitCode = 1;
    return;
  }

  try {
    // Re-wrap the master with the new SSH public key.
    const newTier = StandardTier.fromSshKey(newKeyInfo.publicKeyLine);
    const wrappedNew = await ring.withMaster(async (master) => newTier.wrap(master));
    const wrappedBlob = wrappedNew.envelope;
    const wrappedBlobBase64 = Buffer.from(wrappedBlob).toString('base64');

    // Extract the base64 key blob from the public key line
    const pubKeyParts = newKeyInfo.publicKeyLine.trim().split(/\s+/);
    const newPublicKeyBase64 = pubKeyParts.length >= 2 ? pubKeyParts[1] : pubKeyParts[0];

    // Call POST /v1/rotate-start with the old key for auth
    const { createSyncHttpClientFromConfig } = await import('../../sync/client-factory.js');
    const { DatabaseManager } = await import('../../storage/database-manager.js');
    const db = new DatabaseManager().getPersonalDb();

    const endpoint = config.endpoint.replace(/\/+$/, '');
    const oldClient = createSyncHttpClientFromConfig(
      {
        endpoint,
        sshKeyPath: config.sshKeyPath ?? undefined,
      },
      db.syncSequence,
    );

    const body = JSON.stringify({ newPublicKey: newPublicKeyBase64, wrappedBlob: wrappedBlobBase64 });
    const bodyBytes = new TextEncoder().encode(body);

    const rotateResponse = await oldClient.post('/v1/rotate-start', bodyBytes);

    if (!rotateResponse.ok) {
      const errBody = await rotateResponse.text();
      console.error(`Failed to start key rotation: ${rotateResponse.status} ${errBody}`);
      process.exitCode = 1;
      return;
    }

    // Upload new wrapped blob to /v1/wrapped-key using the NEW key for auth
    const newClient = createSyncHttpClientFromConfig(
      {
        endpoint,
        sshKeyPath: newKeyInfo.keyPath,
      },
      db.syncSequence,
    );

    const uploadResponse = await newClient.put('/v1/wrapped-key', wrappedBlob);

    if (!uploadResponse.ok) {
      const errBody = await uploadResponse.text();
      console.error(`Failed to upload wrapped key: ${uploadResponse.status} ${errBody}`);
      process.exitCode = 1;
      return;
    }

    // Update the local keyring slot so subsequent launches unlock with
    // the new key. We overwrite the `__personal` slot with the newly-
    // wrapped blob.
    await storage.put('__personal', wrappedNew);

    // Update config with new key fingerprint and keyPath
    config.sshKeyFingerprint = newKeyInfo.fingerprint;
    config.sshKeyPath = newKeyInfo.keyPath;
    await saveConfig(config);

    console.log('Key rotation started. Other devices will be notified on next sync.');
  } finally {
    await ring.lock();
  }
}

// --- Storage + SSH key detection ---

function buildStorage(): KeyStorage<'standard'> {
  if (process.env.CHAOSKB_KEY_STORAGE === 'file') {
    const fsDir = path.join(CHAOSKB_DIR, 'keyring');
    fs.mkdirSync(fsDir, { recursive: true, mode: 0o700 });
    return new FileSystemStorage({ root: fsDir }) as KeyStorage<'standard'>;
  }
  return new OsKeychainStorage<'standard'>({
    service: KEYRING_SERVICE,
    acceptedTiers: ['standard'] as const,
  });
}

function resolveOldKeyPath(configSshKeyPath?: string): string | null {
  if (configSshKeyPath && fs.existsSync(configSshKeyPath)) return configSshKeyPath;
  const sshDir = path.join(os.homedir(), '.ssh');
  const candidates = ['id_ed25519', 'id_rsa'];
  for (const c of candidates) {
    const p = path.join(sshDir, c);
    if (fs.existsSync(p) && fs.existsSync(`${p}.pub`)) {
      return p;
    }
  }
  return null;
}

interface NewSSHKeyInfo {
  publicKeyLine: string;
  fingerprint: string;
  keyPath: string;
}

/**
 * Detect the new SSH key to rotate to.
 *
 * If newKeyPath is provided, reads that key file.
 * Otherwise, auto-detects from common SSH key locations, preferring
 * keys that are NOT the currently configured key.
 */
async function detectNewSSHKey(newKeyPath?: string): Promise<NewSSHKeyInfo | null> {
  if (newKeyPath) {
    return readSSHKeyFromPath(newKeyPath);
  }

  // Auto-detect: try common locations
  const sshDir = path.join(os.homedir(), '.ssh');
  const candidates = [
    { file: 'id_ed25519.pub', keyFile: 'id_ed25519' },
    { file: 'id_rsa.pub', keyFile: 'id_rsa' },
  ];

  for (const { file, keyFile } of candidates) {
    const pubKeyPath = path.join(sshDir, file);
    if (fs.existsSync(pubKeyPath)) {
      const result = await readSSHKeyFromPath(path.join(sshDir, keyFile));
      if (result) return result;
    }
  }

  return null;
}

async function readSSHKeyFromPath(keyPath: string): Promise<NewSSHKeyInfo | null> {
  const pubKeyPath = keyPath.endsWith('.pub') ? keyPath : keyPath + '.pub';
  const privateKeyPath = keyPath.endsWith('.pub') ? keyPath.slice(0, -4) : keyPath;

  try {
    const content = fs.readFileSync(pubKeyPath, 'utf-8').trim();
    const parsed = parseSshPublicKey(content);
    return {
      publicKeyLine: content,
      fingerprint: parsed.fingerprint,
      keyPath: privateKeyPath,
    };
  } catch {
    return null;
  }
}
