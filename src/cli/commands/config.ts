import * as fs from 'node:fs';
import * as os from 'node:os';
import * as readline from 'node:readline';
import * as path from 'node:path';
import {
  KeyRing,
  StandardTier,
  MaximumTier,
  OsKeychainStorage,
  FileSystemStorage,
  type KeyStorage,
  type WrappedKey,
} from '@de-otio/keyring';
import { loadConfig, saveConfig, CHAOSKB_DIR } from './setup.js';
import { SecurityTier } from '../../crypto/types.js';
import { KEYRING_SERVICE, FILE_KEY_PATH } from '../bootstrap.js';

const TIER_ORDER: SecurityTier[] = [
  SecurityTier.Standard,
  SecurityTier.Enhanced,
  SecurityTier.Maximum,
];

function tierIndex(tier: string): number {
  return TIER_ORDER.indexOf(tier as SecurityTier);
}

function prompt(rl: readline.Interface, question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
}

function buildStorage<K extends 'standard' | 'maximum'>(kind: K): KeyStorage<K> {
  if (process.env.CHAOSKB_KEY_STORAGE === 'file') {
    const fsDir = path.join(CHAOSKB_DIR, 'keyring');
    fs.mkdirSync(fsDir, { recursive: true, mode: 0o700 });
    return new FileSystemStorage<K>({
      root: fsDir,
      acceptedTiers: [kind] as const,
    }) as KeyStorage<K>;
  }
  return new OsKeychainStorage<K>({
    service: KEYRING_SERVICE,
    acceptedTiers: [kind] as const,
  });
}

function resolveSshKeyPath(configSshKeyPath?: string): string | null {
  if (configSshKeyPath && fs.existsSync(configSshKeyPath)) return configSshKeyPath;
  const sshDir = path.join(os.homedir(), '.ssh');
  for (const c of ['id_ed25519', 'id_rsa']) {
    const p = path.join(sshDir, c);
    if (fs.existsSync(p) && fs.existsSync(`${p}.pub`)) return p;
  }
  return null;
}

/**
 * Upgrade security tier.
 *
 * Standard → Maximum: unlock master via the current Standard tier,
 * then re-wrap under a passphrase-derived KEK via keyring's `MaximumTier`.
 *
 * Note: The Enhanced tier (BIP39 mnemonic) is deprecated. New upgrades
 * only support "maximum".
 */
export async function upgradeTierCommand(
  tier: string,
  options?: { dryRun?: boolean },
): Promise<void> {
  const dryRun = options?.dryRun ?? false;
  // Validate tier argument — only 'maximum' is accepted for new upgrades
  if (tier !== 'maximum') {
    if (tier === 'enhanced') {
      console.error('The "enhanced" tier is deprecated. Use "maximum" instead.');
    } else {
      console.error(`Invalid tier: "${tier}". Must be "maximum".`);
    }
    process.exitCode = 1;
    return;
  }

  const config = await loadConfig();
  if (!config) {
    console.error('ChaosKB is not configured. Run `chaoskb-mcp setup` first.');
    process.exitCode = 1;
    return;
  }

  const currentIndex = tierIndex(config.securityTier);
  const targetIndex = tierIndex(tier);

  if (targetIndex <= currentIndex) {
    console.error(`Already at "${config.securityTier}" tier or higher.`);
    process.exitCode = 1;
    return;
  }

  // Locate and unlock the current master key via StandardTier.
  const sshKeyPath = resolveSshKeyPath(config.sshKeyPath);
  if (!sshKeyPath) {
    console.error('Master key not found. Ensure your OS keyring is accessible.');
    process.exitCode = 1;
    return;
  }

  const standardStorage = buildStorage<'standard'>('standard');
  const currentWrapped: WrappedKey | null = await standardStorage.get('__personal');
  if (!currentWrapped) {
    console.error('Master key not found. Ensure your OS keyring is accessible.');
    process.exitCode = 1;
    return;
  }

  if (dryRun) {
    console.log(
      '[dry-run] Would upgrade security tier from "%s" to "%s".',
      config.securityTier,
      tier,
    );
    console.log('[dry-run] This will:');
    console.log('[dry-run]   - Derive a wrapping key from your passphrase using Argon2id');
    console.log('[dry-run]   - Encrypt the master key with the wrapping key');
    console.log('[dry-run]   - Write encrypted key blob to ~/.chaoskb/master-key.enc');
    console.log('[dry-run]   - Remove the master key from the OS keyring');
    console.log('[dry-run] No changes made.');
    return;
  }

  await upgradeToMaximum(sshKeyPath, currentWrapped, config);
}

async function upgradeToMaximum(
  sshKeyPath: string,
  currentWrapped: WrappedKey,
  config: { securityTier: string; projects: Array<{ name: string; createdAt: string }> },
): Promise<void> {
  if (!process.stdin.isTTY) {
    console.error('Maximum tier requires an interactive terminal for passphrase entry.');
    process.exitCode = 1;
    return;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  let passphrase: string;
  try {
    passphrase = await prompt(rl, 'Enter new passphrase (min 25 characters): ');
    if (passphrase.length < 25) {
      console.error('Passphrase must be at least 25 characters (e.g. 5+ diceware words).');
      process.exitCode = 1;
      return;
    }

    const confirm = await prompt(rl, 'Confirm passphrase: ');
    if (passphrase !== confirm) {
      console.error('Passphrases do not match.');
      process.exitCode = 1;
      return;
    }

    if (config.securityTier === SecurityTier.Enhanced) {
      console.log('');
      console.log('Note: Your 24-word recovery key will no longer be valid after this upgrade.');
      console.log('Your passphrase becomes your only recovery factor.');
      console.log('');
    }
  } finally {
    rl.close();
  }

  console.log('Deriving key with Argon2id (this may take a moment)...');

  // 1. Unlock the current master via StandardTier + stored wrapped blob.
  const sshPublicKeyLine = fs.readFileSync(`${sshKeyPath}.pub`, 'utf-8').trim();
  const sshPrivateKeyPem = fs.readFileSync(sshKeyPath, 'utf-8');
  const standardStorage = buildStorage<'standard'>('standard');
  const standardTier = StandardTier.fromSshKey(sshPublicKeyLine);
  const ring = new KeyRing({ tier: standardTier, storage: standardStorage });
  try {
    await ring.unlockWithSshKey(sshPrivateKeyPem);
  } catch (err) {
    console.error(
      `Failed to unlock master key: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exitCode = 1;
    return;
  }

  // 2. Wrap the master with MaximumTier under the new passphrase.
  try {
    const maxTier = MaximumTier.fromPassphrase(passphrase);
    const maxWrapped = await ring.withMaster(async (master) => maxTier.wrap(master));

    // Persist to a dedicated storage (filesystem-backed blob file for
    // compatibility with the previous Maximum-tier layout at
    // ~/.chaoskb/master-key.enc).
    const blobPath = path.join(CHAOSKB_DIR, 'master-key.enc');
    const serialisedBlob = serialiseWrappedKey(maxWrapped);
    fs.writeFileSync(blobPath, serialisedBlob, { mode: 0o600 });

    // Verify-after-write: round-trip decrypt the blob we just wrote.
    await verifyRoundTrip(blobPath, passphrase);

    // Verification passed — safe to clear the StandardTier wrapping.
    await ring.delete();

    // Also remove file-based key if it exists (legacy pre-migration state).
    try {
      fs.unlinkSync(FILE_KEY_PATH);
    } catch {
      // File may not exist
    }

    // Update config
    config.securityTier = SecurityTier.Maximum;
    await saveConfig(config);

    console.log('');
    console.log('Security tier upgraded to Maximum.');
    console.log(`Encrypted key written to ${blobPath}`);
    console.log('Your passphrase is now your only recovery factor.');
  } finally {
    await ring.lock();
    // We do our best to forget `currentWrapped` by not retaining a
    // reference past this scope.
    void currentWrapped;
  }
}

/**
 * Serialise a keyring `WrappedKey` to the chaoskb `master-key.enc` file.
 * Uses a JSON schema compatible with keyring's internal serialiser so
 * both halves of the migration can read it — matches the shape written
 * by keyring's own filesystem storage.
 */
function serialiseWrappedKey(w: WrappedKey): string {
  const out: Record<string, unknown> = {
    v: w.v,
    tier: w.tier,
    envelope: Buffer.from(w.envelope).toString('base64'),
    ts: w.ts,
  };
  if (w.kdfParams) {
    if (w.kdfParams.algorithm === 'argon2id') {
      out.kdfParams = {
        algorithm: 'argon2id',
        t: w.kdfParams.t,
        m: w.kdfParams.m,
        p: w.kdfParams.p,
        salt: Buffer.from(w.kdfParams.salt).toString('base64'),
      };
    } else {
      out.kdfParams = {
        algorithm: 'pbkdf2-sha256',
        iterations: w.kdfParams.iterations,
        salt: Buffer.from(w.kdfParams.salt).toString('base64'),
      };
    }
  }
  return JSON.stringify(out, null, 2);
}

/** Parse the serialised form back into a WrappedKey. */
export function parseWrappedKey(json: string): WrappedKey {
  const parsed = JSON.parse(json) as {
    v: number;
    tier: string;
    envelope: string;
    kdfParams?: {
      algorithm: string;
      t?: number;
      m?: number;
      p?: number;
      iterations?: number;
      salt: string;
    };
    sshFingerprint?: string;
    ts: string;
  };
  if (parsed.v !== 1) throw new Error(`unsupported wrapped-key wire version: ${parsed.v}`);
  if (parsed.tier !== 'standard' && parsed.tier !== 'maximum') {
    throw new Error(`unsupported tier kind: ${parsed.tier}`);
  }
  const out: WrappedKey = {
    v: 1,
    tier: parsed.tier,
    envelope: new Uint8Array(Buffer.from(parsed.envelope, 'base64')),
    ts: parsed.ts,
  };
  if (parsed.kdfParams) {
    const saltBytes = new Uint8Array(Buffer.from(parsed.kdfParams.salt, 'base64'));
    if (parsed.kdfParams.algorithm === 'argon2id') {
      out.kdfParams = {
        algorithm: 'argon2id',
        t: parsed.kdfParams.t ?? 0,
        m: parsed.kdfParams.m ?? 0,
        p: parsed.kdfParams.p ?? 0,
        salt: saltBytes,
      };
    } else if (parsed.kdfParams.algorithm === 'pbkdf2-sha256') {
      out.kdfParams = {
        algorithm: 'pbkdf2-sha256',
        iterations: parsed.kdfParams.iterations ?? 0,
        salt: saltBytes,
      };
    }
  }
  if (parsed.sshFingerprint) out.sshFingerprint = parsed.sshFingerprint;
  return out;
}

async function verifyRoundTrip(blobPath: string, passphrase: string): Promise<void> {
  const json = fs.readFileSync(blobPath, 'utf-8');
  const wrapped = parseWrappedKey(json);
  // Construct a temporary MaximumTier (its passphrase is only used for
  // wrap; unwrap reads the passphrase from UnlockInput).
  const tier = MaximumTier.fromPassphrase(passphrase);
  const master = await tier.unwrap(wrapped, { kind: 'passphrase', passphrase });
  master.dispose();
}
