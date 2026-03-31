import { describe, it, expect } from 'vitest';
import sodium from 'sodium-native';
import { createInviteBlob, openInviteBlob, padPayload, unpadPayload } from '../invite.js';
import { parseSSHPublicKey } from '../ssh-keys.js';
import type { SSHKeyInfo } from '../types.js';

/** Generate a test Ed25519 key pair and return SSHKeyInfo + secret key. */
function generateTestKey(): { keyInfo: SSHKeyInfo; secretKey: Uint8Array } {
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES);
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES);
  sodium.crypto_sign_keypair(pk, sk);

  // Build SSH wire format key blob
  const typeStr = Buffer.from('ssh-ed25519');
  const typeLen = Buffer.alloc(4);
  typeLen.writeUInt32BE(typeStr.length);
  const pkLen = Buffer.alloc(4);
  pkLen.writeUInt32BE(pk.length);
  const blob = Buffer.concat([typeLen, typeStr, pkLen, pk]);

  const base64 = blob.toString('base64');
  const keyInfo = parseSSHPublicKey(`ssh-ed25519 ${base64} test@test`);

  return { keyInfo, secretKey: new Uint8Array(sk) };
}

describe('createInviteBlob / openInviteBlob', () => {
  it('round-trip: encrypt then decrypt recovers the project key', () => {
    const sender = generateTestKey();
    const recipient = generateTestKey();
    const projectKey = new Uint8Array(Buffer.from('0123456789abcdef0123456789abcdef', 'hex'));
    const projectId = 'test-project-123';

    const blob = createInviteBlob(projectKey, projectId, sender.keyInfo, recipient.keyInfo);
    const recovered = openInviteBlob(blob, recipient.secretKey, recipient.keyInfo, sender.keyInfo, projectId);

    expect(Buffer.from(recovered).toString('hex')).toBe(Buffer.from(projectKey).toString('hex'));
  });

  it('different ephemeral keys produce different blobs', () => {
    const sender = generateTestKey();
    const recipient = generateTestKey();
    const projectKey = new Uint8Array(32);
    const projectId = 'proj-1';

    const blob1 = createInviteBlob(projectKey, projectId, sender.keyInfo, recipient.keyInfo);
    const blob2 = createInviteBlob(projectKey, projectId, sender.keyInfo, recipient.keyInfo);

    // Blobs should differ (different ephemeral keys + nonces)
    expect(Buffer.from(blob1).equals(Buffer.from(blob2))).toBe(false);
  });

  it('wrong recipient cannot decrypt', () => {
    const sender = generateTestKey();
    const recipient = generateTestKey();
    const wrongRecipient = generateTestKey();
    const projectKey = new Uint8Array(32);
    const projectId = 'proj-1';

    const blob = createInviteBlob(projectKey, projectId, sender.keyInfo, recipient.keyInfo);

    expect(() =>
      openInviteBlob(blob, wrongRecipient.secretKey, wrongRecipient.keyInfo, sender.keyInfo, projectId),
    ).toThrow();
  });

  it('wrong project ID in HKDF prevents decryption', () => {
    const sender = generateTestKey();
    const recipient = generateTestKey();
    const projectKey = new Uint8Array(32);

    const blob = createInviteBlob(projectKey, 'project-a', sender.keyInfo, recipient.keyInfo);

    expect(() =>
      openInviteBlob(blob, recipient.secretKey, recipient.keyInfo, sender.keyInfo, 'project-b'),
    ).toThrow();
  });

  it('blob size is consistent (padded to 512 bytes payload)', () => {
    const sender = generateTestKey();
    const recipient = generateTestKey();

    const smallKey = new Uint8Array(16);
    const largeKey = new Uint8Array(32);

    const blob1 = createInviteBlob(smallKey, 'p1', sender.keyInfo, recipient.keyInfo);
    const blob2 = createInviteBlob(largeKey, 'project-with-a-long-name', sender.keyInfo, recipient.keyInfo);

    // Both blobs should be the same size (padded payload)
    expect(blob1.length).toBe(blob2.length);
  });
});

describe('padPayload / unpadPayload', () => {
  it('round-trip preserves payload', () => {
    const payload = new TextEncoder().encode('hello world');
    const padded = padPayload(payload, 512);
    const recovered = unpadPayload(padded);

    expect(new TextDecoder().decode(recovered)).toBe('hello world');
  });

  it('padded output is exactly the target size', () => {
    const payload = new TextEncoder().encode('test');
    const padded = padPayload(payload, 256);
    expect(padded.length).toBe(256);
  });

  it('throws if payload too large for target', () => {
    const payload = new Uint8Array(600);
    expect(() => padPayload(payload, 512)).toThrow('Payload too large');
  });

  it('empty payload round-trips', () => {
    const padded = padPayload(new Uint8Array(0), 64);
    const recovered = unpadPayload(padded);
    expect(recovered.length).toBe(0);
  });
});
