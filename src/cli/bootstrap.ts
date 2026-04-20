import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { randomBytes } from 'node:crypto';
import {
  KeyRing,
  StandardTier,
  OsKeychainStorage,
  FileSystemStorage,
  OsKeychainUnavailable,
  parseSshPublicKey,
  type KeyStorage,
  type WrappedKey,
} from '@de-otio/keyring';
import { SecureBuffer, asMasterKey } from '@de-otio/crypto-envelope';
import type { MasterKey } from '@de-otio/crypto-envelope';

import { acquireBootstrapLock } from './bootstrap-lock.js';
import type { ChaosKBConfig } from './mcp-server.js';

export const CHAOSKB_DIR = path.join(os.homedir(), '.chaoskb');
export const FILE_KEY_PATH = path.join(CHAOSKB_DIR, 'master.key');

/** OS keychain service name for chaoskb-managed slots. */
export const KEYRING_SERVICE = 'chaoskb';
/** Fallback Ed25519 identity slot names. These live alongside the
 *  personal master in the same service namespace. */
export const IDENTITY_SECRET_SLOT = 'identity-secret';
export const IDENTITY_PUBLIC_SLOT = 'identity-public';

export interface BootstrapOptions {
  /** Override the base directory (default: ~/.chaoskb). For testing. */
  baseDir?: string;
}

function resolveDir(baseDir?: string): string {
  return baseDir ?? CHAOSKB_DIR;
}

/**
 * Build the chaoskb keyring storage. Prefers the OS keychain; falls back
 * to a filesystem store when `CHAOSKB_KEY_STORAGE=file` is set or the OS
 * keychain is unavailable (headless CI, unsupported platform).
 *
 * The filesystem fallback mirrors the previous `master.key` location but
 * uses keyring's `FileSystemStorage` format — slot files under a 0700
 * directory. Wire format is v1 per keyring.
 */
async function buildStorage(baseDir: string): Promise<{
  storage: KeyStorage<'standard'>;
  kind: 'os-keychain' | 'file';
}> {
  const wantFile = process.env.CHAOSKB_KEY_STORAGE === 'file';
  if (wantFile) {
    const fsDir = path.join(baseDir, 'keyring');
    fs.mkdirSync(fsDir, { recursive: true, mode: 0o700 });
    return {
      storage: new FileSystemStorage({ root: fsDir }) as KeyStorage<'standard'>,
      kind: 'file',
    };
  }
  // OS keychain is checked lazily when the first put/get/delete is made.
  return {
    storage: new OsKeychainStorage<'standard'>({
      service: KEYRING_SERVICE,
      acceptedTiers: ['standard'] as const,
    }),
    kind: 'os-keychain',
  };
}

/**
 * Auto-bootstrap ChaosKB on first launch.
 *
 * Creates ~/.chaoskb/, generates a master key, wraps it with the user's
 * SSH public key (via keyring's `StandardTier`), persists the wrapped
 * blob in the OS keychain, initializes the database, and writes
 * config.json — all with standard security tier and no interactive
 * prompts.
 *
 * Idempotent: no-ops if config.json already exists.
 * Concurrency-safe: uses file-based locking to prevent races.
 */
export async function bootstrap(options?: BootstrapOptions): Promise<void> {
  const chaoskbDir = resolveDir(options?.baseDir);
  const configPath = path.join(chaoskbDir, 'config.json');
  const modelsDir = path.join(chaoskbDir, 'models');

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

    // 2. Detect SSH key for zero-config sync and as the keyring tier input.
    const sshResult = await detectSSHKey(chaoskbDir);

    // 3. Generate a random 32-byte master key (plain Uint8Array — we hand
    //    it to keyring which owns its SecureBuffer lifecycle).
    const masterBytes = new Uint8Array(randomBytes(32));
    const masterSb = SecureBuffer.from(Buffer.from(masterBytes));
    const master: MasterKey = asMasterKey(masterSb);

    // Keep a copy for sync registration (pre-upload). Zeroed at the end.
    const masterKeyCopy = Buffer.from(masterBytes);
    masterBytes.fill(0);

    // 4. Wrap the master with the SSH key and persist via keyring.
    let keyringOk = false;
    try {
      if (sshResult.publicKey) {
        const tier = StandardTier.fromSshKey(sshResult.publicKey);
        const { storage } = await buildStorage(chaoskbDir);
        const ring = new KeyRing({ tier, storage });
        await ring.setup(master);
        keyringOk = true;

        if (process.platform === 'darwin') {
          process.stderr.write(
            'Storing encryption key in macOS Keychain.\n' +
              'You may see a system dialog asking to allow keychain access — this is expected.\n',
          );
        }
      }
    } catch (keyringError) {
      // Master not yet disposed — fall through to file fallback.
      if (process.env.CHAOSKB_KEY_STORAGE === 'file' || keyringError instanceof OsKeychainUnavailable) {
        process.stderr.write(
          '\n⚠ OS keyring unavailable. Storing key in ' +
            FILE_KEY_PATH +
            ' (file-based).\n' +
            '  This is less secure than the OS keyring. The key file is readable by any process running as your user.\n\n',
        );
        fs.writeFileSync(path.join(chaoskbDir, 'master.key'), masterKeyCopy.toString('hex'), {
          mode: 0o600,
        });
        keyringOk = true;
      } else {
        master.dispose();
        masterKeyCopy.fill(0);
        throw new Error(
          `Failed to store master key in OS keyring: ${keyringError instanceof Error ? keyringError.message : String(keyringError)}\n\n` +
            '  To fix this, either:\n' +
            '  • Install/configure your OS keyring service (macOS Keychain, Linux Secret Service, Windows Credential Manager)\n' +
            '  • Set CHAOSKB_KEY_STORAGE=file to use file-based key storage (less secure)\n',
        );
      }
    }

    if (!keyringOk && !sshResult.publicKey) {
      // No SSH key at all AND we didn't persist yet — fall back to file
      // storage so the bootstrap can still complete.
      if (process.env.CHAOSKB_KEY_STORAGE === 'file') {
        fs.writeFileSync(path.join(chaoskbDir, 'master.key'), masterKeyCopy.toString('hex'), {
          mode: 0o600,
        });
      } else {
        master.dispose();
        masterKeyCopy.fill(0);
        throw new Error(
          'No SSH key found and CHAOSKB_KEY_STORAGE=file not set. ' +
            'Run `ssh-keygen` or set CHAOSKB_KEY_STORAGE=file to continue.',
        );
      }
    }

    master.dispose();

    // 5. Initialize database
    const { DatabaseManager } = await import('../storage/database-manager.js');
    const dbManager = new DatabaseManager(chaoskbDir);
    const db = dbManager.getPersonalDb();
    db.close();
    dbManager.closeAll();

    // 6. Register with sync server (non-blocking)
    const syncResult = await attemptSyncRegistration(sshResult, masterKeyCopy, chaoskbDir);

    // Zero the copy
    masterKeyCopy.fill(0);

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
async function detectSSHKey(baseDir: string): Promise<SSHDetectionResult> {
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
        const parsed = parseSshPublicKey(content);
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
    const fallback = await generateFallbackKey(baseDir);
    if (fallback) return fallback;
  } catch {
    // Keyring unavailable — continue without sync
  }

  return { publicKey: null, fingerprint: null, keyPath: null, source: 'none' };
}

/**
 * Generate a fallback Ed25519 key pair and store it in the OS keyring.
 * Never written to disk. Returns null if keyring is unavailable.
 *
 * Uses keyring's `OsKeychainStorage` directly at dedicated slot names.
 * Stored as a degenerate `WrappedKey` shape — the slot contract is a
 * `WrappedKey`, so we wrap the raw identity bytes in the `envelope`
 * field and use tier='standard' purely as a placeholder. This is a
 * chaoskb-specific convention; the bytes are not AEAD-wrapped because
 * the whole point is that there's no other key material to wrap them
 * with on a new install.
 */
async function generateFallbackKey(_baseDir: string): Promise<SSHDetectionResult | null> {
  const sodium = (await import('sodium-native')).default as unknown as {
    crypto_sign_PUBLICKEYBYTES: number;
    crypto_sign_SECRETKEYBYTES: number;
    crypto_sign_keypair: (pk: Buffer, sk: Buffer) => void;
  };

  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
  sodium.crypto_sign_keypair(pk, sk);

  try {
    const storage = new OsKeychainStorage<'standard'>({
      service: KEYRING_SERVICE,
      acceptedTiers: ['standard'] as const,
    });
    const now = new Date().toISOString();
    const skWrapped: WrappedKey = {
      v: 1,
      tier: 'standard',
      envelope: new Uint8Array(sk),
      ts: now,
    };
    const pkWrapped: WrappedKey = {
      v: 1,
      tier: 'standard',
      envelope: new Uint8Array(pk),
      ts: now,
    };
    await storage.put(IDENTITY_SECRET_SLOT, skWrapped);
    await storage.put(IDENTITY_PUBLIC_SLOT, pkWrapped);
  } catch {
    sk.fill(0);
    return null;
  }

  // Build the SSH public key line
  const { createHash } = await import('node:crypto');
  const typeStr = Buffer.from('ssh-ed25519');
  const keyBlob = Buffer.concat([uint32BE(typeStr.length), typeStr, uint32BE(pk.length), pk]);
  const base64Blob = keyBlob.toString('base64');
  const fingerprint =
    'SHA256:' + createHash('sha256').update(keyBlob).digest('base64').replace(/=+$/, '');

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
  baseDir: string,
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

    const { challenge } = (await challengeRes.json()) as { challenge: string };

    // Step 2: Sign the challenge using SSHSigner (handles OpenSSH key formats + ssh-agent)
    const { SSHSigner } = await import('../sync/ssh-signer.js');
    const signer = new SSHSigner(ssh.keyPath ?? undefined);
    const { signature: signedChallenge, publicKey: signerPublicKey } =
      await signer.signRegistrationChallenge(challenge);

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

    const regResult = (await response.json()) as { status: string; userId?: string };

    // Existing account — download and store the server's wrapped master.
    if (regResult.status === 'existing') {
      await restoreMasterKey(endpoint, ssh, baseDir);
      return { enabled: true, pending: false, endpoint };
    }

    // New account — wrap master key and upload
    if (masterKeyBuffer.length > 0) {
      await uploadWrappedMasterKey(endpoint, ssh, masterKeyBuffer, baseDir);
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
 * Wrap the master key with the SSH public key and upload to the sync
 * server. Uses keyring's `StandardTier.wrap` so the wire format is v1.
 */
async function uploadWrappedMasterKey(
  endpoint: string,
  ssh: SSHDetectionResult,
  masterKeyBuffer: Buffer,
  _baseDir: string,
): Promise<void> {
  if (!ssh.publicKey) return;

  const tier = StandardTier.fromSshKey(ssh.publicKey);
  const masterSb = SecureBuffer.from(Buffer.from(masterKeyBuffer));
  const master = asMasterKey(masterSb);
  try {
    const wrapped = await tier.wrap(master);
    // Wire format: raw `WrappedKey.envelope` bytes. The server stores
    // them opaquely — only the client (which has the SSH private key) can
    // unwrap them.
    const { createSyncHttpClientFromConfig } = await import('../sync/client-factory.js');
    const { DatabaseManager } = await import('../storage/database-manager.js');
    const db = new DatabaseManager().getPersonalDb();
    const client = createSyncHttpClientFromConfig(
      {
        endpoint,
        sshKeyPath: ssh.keyPath ?? undefined,
      },
      db.syncSequence,
    );

    await client.put('/v1/wrapped-key', wrapped.envelope);
  } finally {
    master.dispose();
  }
}

/**
 * Restore the master key on a new device.
 *
 * Downloads the wrapped master-key blob from the server and persists it
 * verbatim into keyring storage at the `__personal` slot. We also attempt
 * an `unlockWithSshKey` to verify the bytes are usable with the local SSH
 * private key; the unwrapped master is immediately discarded — the
 * keyring stays in its wrapped form on disk, to be unlocked on demand by
 * `initializeDependencies`.
 */
async function restoreMasterKey(
  endpoint: string,
  ssh: SSHDetectionResult,
  baseDir: string,
): Promise<void> {
  if (!ssh.publicKey) return;

  const { createSyncHttpClientFromConfig } = await import('../sync/client-factory.js');
  const { DatabaseManager } = await import('../storage/database-manager.js');
  const db = new DatabaseManager().getPersonalDb();
  const client = createSyncHttpClientFromConfig(
    {
      endpoint,
      sshKeyPath: ssh.keyPath ?? undefined,
    },
    db.syncSequence,
  );

  const response = await client.get('/v1/wrapped-key');

  if (!response.ok) {
    throw new Error(`Failed to download wrapped key: ${response.status}`);
  }

  const wrappedEnvelopeBytes = new Uint8Array(await response.arrayBuffer());

  // Persist to keyring storage as a v1 WrappedKey.
  const wrapped: WrappedKey = {
    v: 1,
    tier: 'standard',
    envelope: wrappedEnvelopeBytes,
    sshFingerprint: ssh.fingerprint ?? undefined,
    ts: new Date().toISOString(),
  };

  const { storage } = await buildStorage(baseDir);
  await storage.put('__personal', wrapped);

  // Verify it's unwrappable with the local SSH key (non-fatal: if the key
  // file is missing, the unlock below will just skip and the unwrap will
  // happen lazily on first MCP tool use).
  if (ssh.keyPath) {
    try {
      const pem = fs.readFileSync(ssh.keyPath, 'utf-8');
      const tier = StandardTier.fromSshKey(ssh.publicKey);
      const ring = new KeyRing({ tier, storage });
      await ring.unlockWithSshKey(pem);
      await ring.lock();
    } catch (err) {
      // Verification failed — surface a diagnostic but leave the blob
      // in place. Unlock failure now is unusual but not catastrophic;
      // the MCP server will retry on tool-call time.
      process.stderr.write(
        `Warning: downloaded wrapped key failed verify-unlock: ${err instanceof Error ? err.message : String(err)}\n`,
      );
    }
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

    const baseDir = path.dirname(configPath);
    const sshResult = await detectSSHKey(baseDir);
    if (!sshResult.publicKey) return;

    const syncResult = await attemptSyncRegistration(sshResult, Buffer.alloc(0), baseDir);

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
