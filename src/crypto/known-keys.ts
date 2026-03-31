import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function getKnownKeysPath(): string {
  return path.join(os.homedir(), '.chaoskb', 'known_keys.json');
}

interface PinnedKey {
  fingerprint: string;
  publicKey: string;
  source: string;
  firstSeen: string;
  verifiedAt: string;
}

type KnownKeysStore = Record<string, PinnedKey>;

/**
 * Trust on First Use (TOFU) key pinning for invite recipients.
 *
 * When we first see a recipient's public key (from GitHub, GitLab, or direct),
 * we pin it. On subsequent invites, we check if the key has changed.
 * A key mismatch triggers a warning; a conflict with an independent source
 * is a hard block.
 */

function loadStore(): KnownKeysStore {
  try {
    return JSON.parse(fs.readFileSync(getKnownKeysPath(), 'utf-8'));
  } catch {
    return {};
  }
}

function saveStore(store: KnownKeysStore): void {
  const dir = path.dirname(getKnownKeysPath());
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(getKnownKeysPath(), JSON.stringify(store, null, 2), { mode: 0o600 });
}

/**
 * Pin a key for an identifier (e.g., "github:alice").
 * Throws if the identifier is already pinned with a different fingerprint.
 */
export function pinKey(
  identifier: string,
  fingerprint: string,
  publicKey: string,
  source: string,
): void {
  const store = loadStore();
  const existing = store[identifier];

  if (existing && existing.fingerprint !== fingerprint) {
    throw new KeyMismatchError(
      identifier,
      existing.fingerprint,
      fingerprint,
      existing.source,
      source,
    );
  }

  if (existing && existing.fingerprint === fingerprint) {
    // Same key — update verifiedAt
    existing.verifiedAt = new Date().toISOString();
    saveStore(store);
    return;
  }

  // New key — pin it
  store[identifier] = {
    fingerprint,
    publicKey,
    source,
    firstSeen: new Date().toISOString(),
    verifiedAt: new Date().toISOString(),
  };
  saveStore(store);
}

/**
 * Get a pinned key by identifier.
 */
export function getPinnedKey(identifier: string): PinnedKey | null {
  const store = loadStore();
  return store[identifier] ?? null;
}

/**
 * Check a key against the pin store.
 */
export function checkKeyPin(
  identifier: string,
  fingerprint: string,
): 'match' | 'mismatch' | 'new' {
  const store = loadStore();
  const existing = store[identifier];

  if (!existing) return 'new';
  if (existing.fingerprint === fingerprint) return 'match';
  return 'mismatch';
}

/**
 * Update a pinned key after verified rotation (e.g., new key confirmed on GitHub).
 */
export function updatePinnedKey(
  identifier: string,
  fingerprint: string,
  publicKey: string,
  source: string,
): void {
  const store = loadStore();
  store[identifier] = {
    fingerprint,
    publicKey,
    source,
    firstSeen: store[identifier]?.firstSeen ?? new Date().toISOString(),
    verifiedAt: new Date().toISOString(),
  };
  saveStore(store);
}

export class KeyMismatchError extends Error {
  constructor(
    public readonly identifier: string,
    public readonly pinnedFingerprint: string,
    public readonly newFingerprint: string,
    public readonly pinnedSource: string,
    public readonly newSource: string,
  ) {
    super(
      `Key mismatch for ${identifier}:\n` +
      `  Pinned:   ${pinnedFingerprint} (source: ${pinnedSource})\n` +
      `  Received: ${newFingerprint} (source: ${newSource})\n` +
      `This may indicate a compromised key source. The operation was blocked.`,
    );
    this.name = 'KeyMismatchError';
  }
}
