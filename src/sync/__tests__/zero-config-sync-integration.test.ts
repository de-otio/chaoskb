import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execSync } from 'node:child_process';

// --- Sequence Counter Integration ---

import { SequenceCounter } from '../sequence.js';

describe('SequenceCounter integration', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'chaoskb-seq-int-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('persists across multiple instances (simulating process restart)', () => {
    const filePath = join(tmpDir, 'sequence');

    const counter1 = new SequenceCounter(filePath);
    expect(counter1.next()).toBe(1);
    expect(counter1.next()).toBe(2);
    expect(counter1.next()).toBe(3);

    // Simulate process restart
    const counter2 = new SequenceCounter(filePath);
    expect(counter2.next()).toBe(4);
    expect(counter2.next()).toBe(5);
  });

  it('handles concurrent counters on different files', () => {
    const counter1 = new SequenceCounter(join(tmpDir, 'seq1'));
    const counter2 = new SequenceCounter(join(tmpDir, 'seq2'));

    expect(counter1.next()).toBe(1);
    expect(counter2.next()).toBe(1);
    expect(counter1.next()).toBe(2);
    expect(counter2.next()).toBe(2);
  });
});

// --- SSH Signer + Sequence Integration ---

import { SSHSigner } from '../ssh-signer.js';

describe('SSHSigner with sequence integration', () => {
  let tmpDir: string;
  let keyPath: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'chaoskb-signer-int-'));

    // Use ssh-keygen instead of generateKeyPairSync to avoid OpenSSL
    // compatibility issues with PKCS8 Ed25519 keys on Node 20.
    keyPath = join(tmpDir, 'id_ed25519');
    execSync(`ssh-keygen -t ed25519 -f "${keyPath}" -N "" -C "test@test"`, {
      stdio: 'pipe',
    });
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('produces different signatures for different sequence numbers', async () => {
    const signer = new SSHSigner(keyPath);

    const result1 = await signer.signRequest('GET', '/v1/blobs', 1);
    const result2 = await signer.signRequest('GET', '/v1/blobs', 2);

    expect(result1.authorization).not.toBe(result2.authorization);
    expect(result1.sequence).toBe(1);
    expect(result2.sequence).toBe(2);
  });

  it('includes public key in response', async () => {
    const signer = new SSHSigner(keyPath);
    const result = await signer.signRequest('GET', '/v1/blobs', 1);

    expect(result.publicKey).toBeTruthy();
    expect(result.publicKey.length).toBeGreaterThan(10);
  });

  it('uses SSH-Signature authorization format', async () => {
    const signer = new SSHSigner(keyPath);
    const result = await signer.signRequest('PUT', '/v1/blobs/b_1', 5, new Uint8Array([1, 2, 3]));

    expect(result.authorization).toMatch(/^SSH-Signature /);
  });
});

// Invite crypto and TOFU key-pinning tests were removed with the
// in-tree implementations — those flows now live in `@de-otio/keyring`
// (age-based invite, `KnownKeys` TOFU) and are covered by keyring's own
// test suite.
