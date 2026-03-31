import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// Mock the KNOWN_KEYS_PATH to use a temp directory
const tmpDir = mkdtempSync(join(tmpdir(), 'chaoskb-keys-'));
vi.mock('node:os', async () => {
  const actual = await vi.importActual<typeof import('node:os')>('node:os');
  return { ...actual, homedir: () => tmpDir };
});

import { pinKey, getPinnedKey, checkKeyPin, updatePinnedKey, KeyMismatchError } from '../known-keys.js';
import { mkdirSync } from 'node:fs';

describe('known-keys TOFU', () => {
  beforeEach(() => {
    mkdirSync(join(tmpDir, '.chaoskb'), { recursive: true });
  });

  afterEach(() => {
    rmSync(join(tmpDir, '.chaoskb'), { recursive: true, force: true });
  });

  it('pins a new key', () => {
    pinKey('github:alice', 'SHA256:abc', 'ssh-ed25519 AAAA', 'github');
    const pinned = getPinnedKey('github:alice');

    expect(pinned).not.toBeNull();
    expect(pinned!.fingerprint).toBe('SHA256:abc');
    expect(pinned!.source).toBe('github');
  });

  it('checkKeyPin returns "new" for unknown identifier', () => {
    expect(checkKeyPin('github:unknown', 'SHA256:xyz')).toBe('new');
  });

  it('checkKeyPin returns "match" for same fingerprint', () => {
    pinKey('github:bob', 'SHA256:def', 'ssh-ed25519 BBBB', 'github');
    expect(checkKeyPin('github:bob', 'SHA256:def')).toBe('match');
  });

  it('checkKeyPin returns "mismatch" for different fingerprint', () => {
    pinKey('github:carol', 'SHA256:ghi', 'ssh-ed25519 CCCC', 'github');
    expect(checkKeyPin('github:carol', 'SHA256:different')).toBe('mismatch');
  });

  it('pinKey throws KeyMismatchError on fingerprint conflict', () => {
    pinKey('github:dave', 'SHA256:jkl', 'ssh-ed25519 DDDD', 'github');

    expect(() =>
      pinKey('github:dave', 'SHA256:different', 'ssh-ed25519 EEEE', 'github'),
    ).toThrow(KeyMismatchError);
  });

  it('pinKey is a no-op for same fingerprint (updates verifiedAt)', () => {
    pinKey('github:eve', 'SHA256:mno', 'ssh-ed25519 FFFF', 'github');
    const first = getPinnedKey('github:eve');

    // Pin again with same fingerprint — should not throw
    pinKey('github:eve', 'SHA256:mno', 'ssh-ed25519 FFFF', 'github');
    const second = getPinnedKey('github:eve');

    expect(second!.firstSeen).toBe(first!.firstSeen);
  });

  it('updatePinnedKey replaces the key (for verified rotations)', () => {
    pinKey('github:frank', 'SHA256:old', 'ssh-ed25519 OLD', 'github');
    updatePinnedKey('github:frank', 'SHA256:new', 'ssh-ed25519 NEW', 'github');

    const pinned = getPinnedKey('github:frank');
    expect(pinned!.fingerprint).toBe('SHA256:new');
    expect(pinned!.publicKey).toBe('ssh-ed25519 NEW');
  });

  it('getPinnedKey returns null for unknown identifier', () => {
    expect(getPinnedKey('github:nobody')).toBeNull();
  });
});
