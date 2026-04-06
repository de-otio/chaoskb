import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync, readFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateKeyPairSync, createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { execSync } from 'node:child_process';
import { SSHSigner } from '../ssh-signer.js';

describe('SSHSigner', () => {
  const testDir = join(tmpdir(), `chaoskb-ssh-signer-test-${Date.now()}`);
  const keyPath = join(testDir, 'id_ed25519');
  const pubKeyPath = join(testDir, 'id_ed25519.pub');

  beforeAll(() => {
    mkdirSync(testDir, { recursive: true });

    // Generate an Ed25519 key pair for testing
    const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    writeFileSync(keyPath, privateKey, 'utf-8');
    writeFileSync(pubKeyPath, `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@example.com`, 'utf-8');

    // Store PEM for verification reference
    void publicKey;
  });

  afterAll(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  describe('buildCanonical', () => {
    it('should construct the canonical string correctly', () => {
      const signer = new SSHSigner(keyPath);
      const canonical = signer.buildCanonical('PUT', '/v1/blobs/b_abc123', '2026-03-20T10:00:00.000Z', 1, 'deadbeef');
      expect(canonical).toBe('chaoskb-auth\nPUT /v1/blobs/b_abc123\n2026-03-20T10:00:00.000Z\n1\ndeadbeef');
    });

    it('should handle GET with empty body hash', () => {
      const signer = new SSHSigner(keyPath);
      const canonical = signer.buildCanonical('GET', '/v1/blobs', '2026-03-20T10:00:00.000Z', 1, '');
      expect(canonical).toBe('chaoskb-auth\nGET /v1/blobs\n2026-03-20T10:00:00.000Z\n1\n');
    });
  });

  describe('computeBodyHash', () => {
    it('should compute SHA-256 hex digest of base64-encoded body', () => {
      const signer = new SSHSigner(keyPath);
      const body = new TextEncoder().encode('hello world');
      const hash = signer.computeBodyHash(body);

      // Body is base64-encoded to match Lambda function URL behavior
      const base64Body = Buffer.from(body).toString('base64');
      const expected = createHash('sha256').update(base64Body).digest('hex');
      expect(hash).toBe(expected);
    });

    it('should return empty string for undefined body', () => {
      const signer = new SSHSigner(keyPath);
      expect(signer.computeBodyHash(undefined)).toBe('');
    });

    it('should return empty string for empty Uint8Array', () => {
      const signer = new SSHSigner(keyPath);
      expect(signer.computeBodyHash(new Uint8Array(0))).toBe('');
    });
  });

  describe('timestamp generation', () => {
    it('should generate ISO 8601 timestamp in signRequest', async () => {
      const signer = new SSHSigner(keyPath);
      const before = new Date().toISOString();
      const { timestamp } = await signer.signRequest('GET', '/v1/blobs', 1);
      const after = new Date().toISOString();

      // Timestamp should be a valid ISO string between before and after
      expect(new Date(timestamp).toISOString()).toBe(timestamp);
      expect(timestamp >= before).toBe(true);
      expect(timestamp <= after).toBe(true);
    });
  });

  describe('signRequest', () => {
    it('should return authorization header with correct format', async () => {
      const signer = new SSHSigner(keyPath);
      const { authorization, timestamp, sequence } = await signer.signRequest('GET', '/v1/blobs', 1);

      expect(authorization).toMatch(/^SSH-Signature .+$/);
      expect(timestamp).toBeTruthy();
      expect(sequence).toBe(1);
    });

    it('should include body hash in canonical string for PUT', async () => {
      const signer = new SSHSigner(keyPath);
      const body = new Uint8Array([1, 2, 3, 4]);
      const { authorization } = await signer.signRequest('PUT', '/v1/blobs/b_test', 2, body);

      expect(authorization).toMatch(/^SSH-Signature /);
    });
  });

  describe('signRegistrationChallenge', () => {
    it('should return signature and publicKey as base64 strings', async () => {
      const signer = new SSHSigner(keyPath);
      const nonce = 'test-nonce-abc123';
      const result = await signer.signRegistrationChallenge(nonce);

      expect(result).toHaveProperty('signature');
      expect(result).toHaveProperty('publicKey');
      expect(typeof result.signature).toBe('string');
      expect(typeof result.publicKey).toBe('string');
      // signature should be valid base64
      expect(() => Buffer.from(result.signature, 'base64')).not.toThrow();
      expect(Buffer.from(result.signature, 'base64').length).toBeGreaterThan(0);
    });

    it('should produce different signatures for different nonces', async () => {
      const signer = new SSHSigner(keyPath);
      const result1 = await signer.signRegistrationChallenge('nonce-1');
      const result2 = await signer.signRegistrationChallenge('nonce-2');

      expect(result1.signature).not.toBe(result2.signature);
      // Same key, so publicKey should be the same
      expect(result1.publicKey).toBe(result2.publicKey);
    });
  });
});

/**
 * Tests for OpenSSH-format private key parsing.
 *
 * These tests use `ssh-keygen` to generate keys in native OpenSSH format
 * (-----BEGIN OPENSSH PRIVATE KEY-----), which forces the parseOpenSSHPrivateKey
 * fallback path when Node's createPrivateKey cannot handle the format.
 *
 * The SSHSigner.signRequest / signRegistrationChallenge methods are used to
 * exercise the parser indirectly since parseOpenSSHPrivateKey is not exported.
 */
describe('SSHSigner with OpenSSH-format keys', () => {
  const opensshDir = join(tmpdir(), `chaoskb-openssh-test-${Date.now()}`);

  beforeAll(() => {
    mkdirSync(opensshDir, { recursive: true });
  });

  afterAll(() => {
    rmSync(opensshDir, { recursive: true, force: true });
  });

  describe('Ed25519 OpenSSH key', () => {
    const ed25519Path = join(opensshDir, 'id_ed25519');

    beforeAll(() => {
      execSync(`ssh-keygen -t ed25519 -f "${ed25519Path}" -N "" -C "test-ed25519@chaoskb"`, {
        stdio: 'pipe',
      });
    });

    it('should sign and produce valid signature via signRegistrationChallenge', async () => {
      const signer = new SSHSigner(ed25519Path);
      const nonce = 'openssh-ed25519-test-nonce';
      const result = await signer.signRegistrationChallenge(nonce);

      expect(result.signature).toBeTruthy();
      expect(result.publicKey).toBeTruthy();

      // Verify the signature is valid by loading the public key and checking
      const pubKeyContent = readFileSync(ed25519Path + '.pub', 'utf-8').trim();
      const pubKeyBase64 = pubKeyContent.split(/\s+/)[1];
      expect(result.publicKey).toBe(pubKeyBase64);

      // Reconstruct the signed data and verify with the public key
      const signedData = Buffer.from(`chaoskb-register\n${nonce}`, 'utf-8');
      const sigBytes = Buffer.from(result.signature, 'base64');

      // Load the public key from the .pub file for verification
      // For ed25519, extract the raw 32-byte key from the SSH wire format
      const keyBlob = Buffer.from(pubKeyBase64, 'base64');
      // SSH wire format: uint32 len, "ssh-ed25519", uint32 len, <32-byte key>
      let off = 0;
      const typeLen = keyBlob.readUInt32BE(off); off += 4 + typeLen;
      const rawKeyLen = keyBlob.readUInt32BE(off); off += 4;
      const rawKey = keyBlob.subarray(off, off + rawKeyLen);

      // Build DER-encoded SPKI for ed25519 public key
      const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
      const pubKeyObj = createPublicKey({
        key: Buffer.concat([spkiPrefix, rawKey]),
        format: 'der',
        type: 'spki',
      });

      const valid = cryptoVerify(null, signedData, pubKeyObj, sigBytes);
      expect(valid).toBe(true);
    });

    it('should sign requests successfully', async () => {
      const signer = new SSHSigner(ed25519Path);
      const result = await signer.signRequest('GET', '/v1/blobs', 1);

      expect(result.authorization).toMatch(/^SSH-Signature .+$/);
      expect(result.timestamp).toBeTruthy();
      expect(result.sequence).toBe(1);
    });
  });

  describe('RSA OpenSSH key', () => {
    const rsaPath = join(opensshDir, 'id_rsa');

    beforeAll(() => {
      execSync(`ssh-keygen -t rsa -b 2048 -f "${rsaPath}" -N "" -C "test-rsa@chaoskb"`, {
        stdio: 'pipe',
      });
    });

    it('should sign and produce valid signature via signRegistrationChallenge', async () => {
      const signer = new SSHSigner(rsaPath);
      const nonce = 'openssh-rsa-test-nonce';
      const result = await signer.signRegistrationChallenge(nonce);

      expect(result.signature).toBeTruthy();
      expect(result.publicKey).toBeTruthy();

      // Verify the signature with the public key
      const pubKeyContent = readFileSync(rsaPath + '.pub', 'utf-8').trim();
      const pubKeyBase64 = pubKeyContent.split(/\s+/)[1];
      expect(result.publicKey).toBe(pubKeyBase64);

      // Extract RSA public key from SSH wire format and verify
      const signedData = Buffer.from(`chaoskb-register\n${nonce}`, 'utf-8');
      const sigBytes = Buffer.from(result.signature, 'base64');

      // Parse the SSH public key blob to extract e and n for RSA
      const keyBlob = Buffer.from(pubKeyBase64, 'base64');
      let off = 0;
      function readSSHStr(): Buffer {
        const len = keyBlob.readUInt32BE(off); off += 4;
        const data = keyBlob.subarray(off, off + len); off += len;
        return data;
      }
      readSSHStr(); // key type "ssh-rsa"
      const e = readSSHStr();
      const n = readSSHStr();

      const pubKeyObj = createPublicKey({
        key: {
          kty: 'RSA',
          n: n.toString('base64url'),
          e: e.toString('base64url'),
        },
        format: 'jwk',
      });

      const valid = cryptoVerify('sha256', signedData, pubKeyObj, sigBytes);
      expect(valid).toBe(true);
    });

    it('should sign requests successfully', async () => {
      const signer = new SSHSigner(rsaPath);
      const result = await signer.signRequest('PUT', '/v1/blobs/b_test', 42, new Uint8Array([10, 20, 30]));

      expect(result.authorization).toMatch(/^SSH-Signature .+$/);
      expect(result.timestamp).toBeTruthy();
      expect(result.sequence).toBe(42);
      expect(result.publicKey).toBeTruthy();
    });
  });

  describe('unsupported key', () => {
    it('should throw for passphrase-protected keys', async () => {
      const protectedPath = join(opensshDir, 'id_protected');
      execSync(`ssh-keygen -t ed25519 -f "${protectedPath}" -N "testpass" -C "protected@chaoskb"`, {
        stdio: 'pipe',
      });

      const signer = new SSHSigner(protectedPath);
      await expect(signer.signRegistrationChallenge('test')).rejects.toThrow();
    });
  });
});
