import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { acquireBootstrapLock } from './bootstrap-lock.js';
import type { ChaosKBConfig } from './mcp-server.js';

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

    // Copy master key bytes before disposing (needed for sync registration)
    const masterKeyBytes = Buffer.from(masterKey.buffer);
    masterKey.dispose();

    // 4. Initialize database
    const { DatabaseManager } = await import('../storage/database-manager.js');
    const dbManager = new DatabaseManager(chaoskbDir);
    const db = dbManager.getPersonalDb();
    db.close();
    dbManager.closeAll();

    // 5. Detect SSH key for zero-config sync
    const sshResult = await detectSSHKey();

    // 6. Register with sync server (non-blocking)
    const syncResult = await attemptSyncRegistration(sshResult, masterKeyBytes);

    // Zero the copy
    masterKeyBytes.fill(0);

    // 7. Write config
    const config: ChaosKBConfig = {
      securityTier: 'standard',
      projects: [],
      syncEnabled: syncResult.enabled,
      syncPending: syncResult.pending,
      ...(syncResult.endpoint && { endpoint: syncResult.endpoint }),
      ...(sshResult.fingerprint && { sshKeyFingerprint: sshResult.fingerprint }),
      ...(sshResult.keyPath && { sshKeyPath: sshResult.keyPath }),
    };
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });

    // 8. Log sync status
    if (syncResult.enabled) {
      process.stderr.write('Sync enabled. Your knowledge base will sync automatically.\n');
    } else if (syncResult.pending) {
      process.stderr.write('Sync server unreachable. Will retry on next launch.\n');
    } else if (!sshResult.publicKey) {
      process.stderr.write(
        '\nNo SSH key found. Using a generated key stored in your OS keyring.\n' +
        'Multi-device sync requires an SSH key — run ssh-keygen to create one,\n' +
        'then: chaoskb-mcp config rotate-key\n\n',
      );
    }
  } finally {
    releaseLock();
  }
}

// --- SSH key detection ---

interface SSHDetectionResult {
  publicKey: string | null; // full public key line (e.g., "ssh-ed25519 AAAA... comment")
  fingerprint: string | null;
  keyPath: string | null;
  source: 'agent' | 'file' | 'none';
}

/**
 * Detect the user's SSH key for zero-config sync.
 *
 * Priority: ssh-agent (Ed25519 > RSA) → filesystem (id_ed25519 > id_rsa)
 * If no SSH key found, returns source: 'none'.
 */
async function detectSSHKey(): Promise<SSHDetectionResult> {
  // Respect opt-out
  if (process.env.CHAOSKB_SYNC === 'off') {
    return { publicKey: null, fingerprint: null, keyPath: null, source: 'none' };
  }

  // Try ssh-agent first
  if (process.env.SSH_AUTH_SOCK) {
    try {
      const { listSSHAgentKeys } = await import('../crypto/ssh-agent.js');
      const keys = await listSSHAgentKeys();

      // Prefer Ed25519 over RSA
      const ed25519 = keys.find((k) => k.type === 'ed25519');
      const rsa = keys.find((k) => k.type === 'rsa');
      const picked = ed25519 ?? rsa;

      if (picked) {
        return {
          publicKey: `ssh-${picked.type === 'ed25519' ? 'ed25519' : 'rsa'} ${Buffer.from(picked.publicKeyBytes).toString('base64')}`,
          fingerprint: picked.fingerprint,
          keyPath: null,
          source: 'agent',
        };
      }
    } catch {
      // Agent not available or failed — fall through to filesystem
    }
  }

  // Try filesystem
  const sshDir = path.join(os.homedir(), '.ssh');
  const candidates = [
    { file: 'id_ed25519.pub', keyFile: 'id_ed25519' },
    { file: 'id_rsa.pub', keyFile: 'id_rsa' },
  ];

  for (const { file, keyFile } of candidates) {
    const pubKeyPath = path.join(sshDir, file);
    if (fs.existsSync(pubKeyPath)) {
      try {
        const content = fs.readFileSync(pubKeyPath, 'utf-8').trim();
        const { parseSSHPublicKey } = await import('../crypto/ssh-keys.js');
        const parsed = parseSSHPublicKey(content);
        return {
          publicKey: content,
          fingerprint: parsed.fingerprint,
          keyPath: path.join(sshDir, keyFile),
          source: 'file',
        };
      } catch {
        // Malformed key file — skip
        continue;
      }
    }
  }

  // No SSH key found — try generating a fallback key in keyring
  try {
    const fallback = await generateFallbackKey();
    if (fallback) return fallback;
  } catch {
    // Keyring unavailable — continue without sync
  }

  return { publicKey: null, fingerprint: null, keyPath: null, source: 'none' };
}

/**
 * Generate a fallback Ed25519 key pair and store it in the OS keyring.
 * Never written to disk. Returns null if keyring is unavailable.
 */
async function generateFallbackKey(): Promise<SSHDetectionResult | null> {
  const sodium = (await import('sodium-native')).default as any;
  const { KeyringService } = await import('../crypto/keyring.js');

  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES as number);
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES as number);
  sodium.crypto_sign_keypair(pk, sk);

  try {
    // Store secret key in keyring only (never on disk)
    const keyring = new KeyringService();
    const { SecureBuffer } = await import('../crypto/secure-buffer.js');
    await keyring.store('chaoskb', 'identity-secret', SecureBuffer.from(sk));
    await keyring.store('chaoskb', 'identity-public', SecureBuffer.from(pk));
  } catch {
    sk.fill(0);
    return null;
  }

  // Build the SSH public key line
  const { createHash } = await import('node:crypto');
  const typeStr = Buffer.from('ssh-ed25519');
  const keyBlob = Buffer.concat([
    uint32BE(typeStr.length), typeStr,
    uint32BE(pk.length), pk,
  ]);
  const base64Blob = keyBlob.toString('base64');
  const fingerprint = 'SHA256:' + createHash('sha256').update(keyBlob).digest('base64').replace(/=+$/, '');

  sk.fill(0);

  return {
    publicKey: `ssh-ed25519 ${base64Blob}`,
    fingerprint,
    keyPath: null,
    source: 'none', // still 'none' — it's a generated key, not a user's SSH key
  };
}

function uint32BE(n: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(n);
  return buf;
}

// --- Sync registration ---

interface SyncRegistrationResult {
  enabled: boolean;
  pending: boolean;
  endpoint: string | null;
}

const DEFAULT_SYNC_ENDPOINT = 'https://sync.chaoskb.com';

/**
 * Attempt to register with the sync server during bootstrap.
 *
 * Non-blocking: if the server is unreachable, returns pending=true
 * and the next launch will retry.
 */
async function attemptSyncRegistration(
  ssh: SSHDetectionResult,
  masterKeyBuffer: Buffer,
): Promise<SyncRegistrationResult> {
  if (process.env.CHAOSKB_SYNC === 'off' || !ssh.publicKey) {
    return { enabled: false, pending: false, endpoint: null };
  }

  const endpoint = process.env.CHAOSKB_SYNC_ENDPOINT ?? DEFAULT_SYNC_ENDPOINT;

  // Extract the base64 key blob from the full SSH public key line
  // e.g., "ssh-ed25519 AAAA... comment" -> "AAAA..."
  const parts = ssh.publicKey.split(/\s+/);
  const publicKeyBase64 = parts.length >= 2 ? parts[1] : ssh.publicKey;

  try {
    // Step 1: Fetch a registration challenge
    const challengeRes = await fetchWithTimeout(`${endpoint}/v1/register/challenge`, {
      method: 'GET',
    });

    if (!challengeRes.ok) {
      return { enabled: false, pending: true, endpoint };
    }

    const { challenge } = await challengeRes.json() as { challenge: string };

    // Step 2: Sign the challenge using SSHSigner (handles OpenSSH key formats + ssh-agent)
    const { SSHSigner } = await import('../sync/ssh-signer.js');
    const signer = new SSHSigner(ssh.keyPath ?? undefined);
    const { signature: signedChallenge, publicKey: signerPublicKey } = await signer.signRegistrationChallenge(challenge);

    // Use the public key from the signer (correctly extracts base64 blob)
    const regPublicKey = signerPublicKey || publicKeyBase64;

    // Step 3: Register with signed challenge
    const response = await fetchWithTimeout(`${endpoint}/v1/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        publicKey: regPublicKey,
        signedChallenge,
        challengeNonce: challenge,
      }),
    });

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      const status = (body as Record<string, unknown>).status;

      if (status === 'link_required') {
        process.stderr.write(
          'This SSH key is not recognized. To link it to an existing account,\n' +
          'run "chaoskb-mcp devices add" on a device that already has access.\n',
        );
        return { enabled: false, pending: false, endpoint };
      }

      // Already registered — treat as success (key is known to the server)
      if ((body as Record<string, unknown>).error === 'already_registered' || response.status === 409) {
        return { enabled: true, pending: false, endpoint };
      }

      // Other server errors — mark as pending for retry
      return { enabled: false, pending: true, endpoint };
    }

    const regResult = await response.json() as { status: string; userId?: string };

    // Existing account — download and unwrap master key (new-device restore)
    if (regResult.status === 'existing') {
      await restoreMasterKey(endpoint, ssh);
      return { enabled: true, pending: false, endpoint };
    }

    // New account — wrap master key and upload
    if (masterKeyBuffer.length > 0) {
      await uploadWrappedMasterKey(endpoint, ssh, masterKeyBuffer);
    }

    return { enabled: true, pending: false, endpoint };
  } catch {
    // Network error — mark as pending for retry
    return { enabled: false, pending: true, endpoint };
  }
}

/**
 * Fetch with a 10-second timeout.
 */
async function fetchWithTimeout(url: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10_000);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Wrap the master key with the SSH public key and upload to the sync server.
 * The wrapped blob is signed with the SSH private key for integrity verification.
 */
async function uploadWrappedMasterKey(
  endpoint: string,
  ssh: SSHDetectionResult,
  masterKeyBuffer: Buffer,
): Promise<void> {
  if (!ssh.publicKey) return;

  const { parseSSHPublicKey } = await import('../crypto/ssh-keys.js');
  const { wrapMasterKey } = await import('../crypto/tiers/standard.js');
  const { SecureBuffer } = await import('../crypto/secure-buffer.js');

  const keyInfo = parseSSHPublicKey(ssh.publicKey);
  const secureMasterKey = SecureBuffer.from(masterKeyBuffer);

  try {
    const wrappedBlob = wrapMasterKey(secureMasterKey, keyInfo);

    const { createSyncHttpClientFromConfig } = await import('../sync/client-factory.js');
    const { DatabaseManager } = await import('../storage/database-manager.js');
    const db = new DatabaseManager().getPersonalDb();
    const client = createSyncHttpClientFromConfig({
      endpoint,
      sshKeyPath: ssh.keyPath ?? undefined,
    }, db.syncSequence);

    await client.put('/v1/wrapped-key', wrappedBlob);
  } finally {
    secureMasterKey.dispose();
  }
}

/**
 * Restore the master key on a new device.
 *
 * Downloads the wrapped master key blob from the server,
 * verifies the signature, unwraps with the SSH private key,
 * and stores in the OS keyring.
 */
async function restoreMasterKey(
  endpoint: string,
  ssh: SSHDetectionResult,
): Promise<void> {
  if (!ssh.publicKey) return;

  const { createSyncHttpClientFromConfig } = await import('../sync/client-factory.js');
  const { DatabaseManager } = await import('../storage/database-manager.js');
  const db = new DatabaseManager().getPersonalDb();
  const client = createSyncHttpClientFromConfig({
    endpoint,
    sshKeyPath: ssh.keyPath ?? undefined,
  }, db.syncSequence);

  const response = await client.get('/v1/wrapped-key');

  if (!response.ok) {
    throw new Error(`Failed to download wrapped key: ${response.status}`);
  }

  const wrappedBlob = new Uint8Array(await response.arrayBuffer());

  // Unwrap with SSH private key
  const { parseSSHPublicKey } = await import('../crypto/ssh-keys.js');
  const keyInfo = parseSSHPublicKey(ssh.publicKey);

  if (keyInfo.type === 'ed25519') {
    const { unwrapMasterKeyEd25519 } = await import('../crypto/tiers/standard.js');
    // Read the private key to get the secret key bytes for unwrapping
    // For Ed25519 unwrap, we need the raw secret key — ssh-agent can sign
    // but can't expose the raw key for crypto_box_seal_open.
    // Fall back to key file for unwrapping.
    if (ssh.keyPath) {
      const keyData = fs.readFileSync(ssh.keyPath, 'utf-8');
      const { createPrivateKey } = await import('node:crypto');
      const keyObj = createPrivateKey({ key: keyData, format: 'pem' });
      const exported = keyObj.export({ type: 'pkcs8', format: 'der' });
      // Ed25519 PKCS8 DER: last 32 bytes are the private key, preceded by 2-byte wrapper
      // The actual key bytes are at offset 16 (after DER headers), 32 bytes of seed + 32 bytes of public
      const derBuf = Buffer.from(exported);
      // Extract the 32-byte seed from the PKCS8 structure
      // PKCS8 for Ed25519: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 [32 bytes seed]
      const seedOffset = derBuf.indexOf(Buffer.from([0x04, 0x20]), 12);
      if (seedOffset === -1) {
        throw new Error('Could not extract Ed25519 seed from private key');
      }
      const seed = derBuf.subarray(seedOffset + 2, seedOffset + 34);

      // Generate the full 64-byte secret key from the seed
      const sodium = (await import('sodium-native')).default as any;
      const fullSk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES as number);
      const fullPk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES as number);
      sodium.crypto_sign_seed_keypair(fullPk, fullSk, seed);

      const masterKey = unwrapMasterKeyEd25519(wrappedBlob, fullSk, fullPk);

      // Store in keyring
      await storeKeyInKeyring(masterKey);
      masterKey.dispose();

      // Zero sensitive buffers
      fullSk.fill(0);
      seed.fill(0);
    } else {
      // Key is in agent only — can't extract raw key for crypto_box_seal_open
      // This is a known limitation: agent-only keys can sign but can't unwrap sealed boxes
      throw new Error(
        'Cannot restore master key: SSH key is in agent only (no key file).\n' +
        'crypto_box_seal_open requires the raw private key. Ensure the key file is available at ~/.ssh/id_ed25519',
      );
    }
  } else {
    // RSA unwrap
    const { unwrapMasterKeyRSA } = await import('../crypto/tiers/standard.js');
    const { createPrivateKey } = await import('node:crypto');
    if (!ssh.keyPath) {
      throw new Error('Cannot restore master key: no RSA key file path');
    }
    const keyData = fs.readFileSync(ssh.keyPath, 'utf-8');
    const rsaPrivKey = createPrivateKey({ key: keyData, format: 'pem' });
    const masterKey = unwrapMasterKeyRSA(wrappedBlob, rsaPrivKey);
    await storeKeyInKeyring(masterKey);
    masterKey.dispose();
  }

  process.stderr.write('Master key restored from sync server. Your knowledge base will sync shortly.\n');
}

/**
 * Retry sync registration on subsequent launches when syncPending is true.
 * Called from the MCP server startup path.
 */
export async function retrySyncRegistration(configPath: string): Promise<void> {
  try {
    const configData = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as ChaosKBConfig;
    if (!configData.syncPending) return;

    const sshResult = await detectSSHKey();
    if (!sshResult.publicKey) return;

    const syncResult = await attemptSyncRegistration(sshResult, Buffer.alloc(0));

    if (syncResult.enabled || !syncResult.pending) {
      // Either succeeded or permanently failed — clear pending
      configData.syncEnabled = syncResult.enabled;
      configData.syncPending = false;
      if (syncResult.endpoint) configData.endpoint = syncResult.endpoint;
      if (sshResult.fingerprint) configData.sshKeyFingerprint = sshResult.fingerprint;
      fs.writeFileSync(configPath, JSON.stringify(configData, null, 2), { mode: 0o600 });
    }
  } catch {
    // Retry failed silently — will try again next launch
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
