import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateKeyPairSync, createHash } from 'node:crypto';
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
    it('should compute SHA-256 hex digest of body', () => {
      const signer = new SSHSigner(keyPath);
      const body = new TextEncoder().encode('hello world');
      const hash = signer.computeBodyHash(body);

      const expected = createHash('sha256').update(body).digest('hex');
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
});
