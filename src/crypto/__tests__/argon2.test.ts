import { describe, it, expect } from 'vitest';
import { deriveFromPassphrase } from '../argon2.js';

describe('Argon2id KDF', { timeout: 30_000 }, () => {
  // Argon2id is intentionally slow (memory-hard); allow 30s for CI runners
  const salt = new Uint8Array(16).fill(0xab);

  it('should derive a 32-byte key', () => {
    const key = deriveFromPassphrase('test passphrase', salt);
    expect(key.length).toBe(32);
    expect(key.isDisposed).toBe(false);
    key.dispose();
  });

  it('should be deterministic with the same passphrase and salt', () => {
    const key1 = deriveFromPassphrase('deterministic test', salt);
    const key2 = deriveFromPassphrase('deterministic test', salt);

    expect(Buffer.from(key1.buffer)).toEqual(Buffer.from(key2.buffer));

    key1.dispose();
    key2.dispose();
  });

  it('should produce different keys for different passphrases', () => {
    const key1 = deriveFromPassphrase('passphrase one', salt);
    const key2 = deriveFromPassphrase('passphrase two', salt);

    expect(Buffer.from(key1.buffer).equals(Buffer.from(key2.buffer))).toBe(false);

    key1.dispose();
    key2.dispose();
  });

  it('should produce different keys for different salts', () => {
    const salt1 = new Uint8Array(16).fill(0x01);
    const salt2 = new Uint8Array(16).fill(0x02);

    const key1 = deriveFromPassphrase('same passphrase', salt1);
    const key2 = deriveFromPassphrase('same passphrase', salt2);

    expect(Buffer.from(key1.buffer).equals(Buffer.from(key2.buffer))).toBe(false);

    key1.dispose();
    key2.dispose();
  });

  it('should return a SecureBuffer', () => {
    const key = deriveFromPassphrase('test', salt);
    expect(key.isDisposed).toBe(false);
    expect(key.length).toBe(32);

    key.dispose();
    expect(key.isDisposed).toBe(true);
    expect(() => key.buffer).toThrow();
  });

  it('should match the spec test vector salt format', () => {
    // From the envelope spec: Argon2id salt = b0b1b2b3b4b5b6b7b8b9babbbcbdbebf
    const specSalt = Uint8Array.from([
      0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
      0xbe, 0xbf,
    ]);

    const key = deriveFromPassphrase('correct horse battery staple extra', specSalt);
    expect(key.length).toBe(32);
    // The derived key should be non-trivial
    expect(Buffer.from(key.buffer).every((b) => b === 0)).toBe(false);
    key.dispose();
  });
});
