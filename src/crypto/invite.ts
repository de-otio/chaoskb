import { createHash, randomBytes } from 'node:crypto';
import sodium from 'sodium-native';

import { aeadEncrypt, aeadDecrypt } from './aead.js';
import { deriveKey } from './hkdf.js';
import { ed25519ToX25519PublicKey, ed25519ToX25519SecretKey } from './ssh-keys.js';
import type { SSHKeyInfo } from './types.js';

const PADDED_PAYLOAD_SIZE = 512;

/**
 * Create an encrypted invite blob for sharing a project key.
 *
 * Uses ephemeral X25519 ECDH + HKDF (with domain separation) + XChaCha20-Poly1305.
 * The sender's and recipient's fingerprints and the project ID are bound into the
 * HKDF info string to prevent cross-context key confusion.
 *
 * Output format: ephemeral_public_key(32) || nonce(24) || ciphertext || tag(16)
 */
export function createInviteBlob(
  projectKey: Uint8Array,
  projectId: string,
  senderKeyInfo: SSHKeyInfo,
  recipientKeyInfo: SSHKeyInfo,
): Uint8Array {
  if (recipientKeyInfo.type !== 'ed25519') {
    throw new Error('Invite crypto currently supports Ed25519 recipients only');
  }

  // Generate ephemeral X25519 key pair
  const ephPk = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
  const ephSk = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES);
  sodium.crypto_box_keypair(ephPk, ephSk);

  // Convert recipient Ed25519 public key to X25519
  const recipientX25519Pk = ed25519ToX25519PublicKey(recipientKeyInfo.publicKeyBytes);

  // ECDH: shared_secret = X25519(ephemeral_secret, recipient_x25519_public)
  const sharedSecret = Buffer.alloc(sodium.crypto_scalarmult_BYTES);
  sodium.crypto_scalarmult(sharedSecret, ephSk, Buffer.from(recipientX25519Pk));

  // Derive encryption key with domain separation
  const info = buildInviteHkdfInfo(senderKeyInfo.fingerprint, recipientKeyInfo.fingerprint, projectId);
  const encryptionKey = deriveKey(new Uint8Array(sharedSecret), info);

  // Pad and encrypt payload
  const payload = JSON.stringify({
    projectKey: Buffer.from(projectKey).toString('base64'),
    projectId,
  });
  const padded = padPayload(new TextEncoder().encode(payload), PADDED_PAYLOAD_SIZE);
  const emptyAAD = new Uint8Array(0);
  const { nonce, ciphertext, tag } = aeadEncrypt(encryptionKey, padded, emptyAAD);

  // Zero sensitive buffers
  ephSk.fill(0);
  sharedSecret.fill(0);
  encryptionKey.fill(0);

  // Output: ephemeral_pk(32) || nonce(24) || ciphertext || tag(16)
  const result = new Uint8Array(ephPk.length + nonce.length + ciphertext.length + tag.length);
  let offset = 0;
  result.set(ephPk, offset); offset += ephPk.length;
  result.set(nonce, offset); offset += nonce.length;
  result.set(ciphertext, offset); offset += ciphertext.length;
  result.set(tag, offset);

  return result;
}

/**
 * Open an encrypted invite blob to recover the project key.
 *
 * @param blob - The full invite blob (ephemeral_pk || nonce || ciphertext || tag)
 * @param recipientEd25519Sk - The recipient's 64-byte Ed25519 secret key
 * @param recipientKeyInfo - The recipient's SSH key info (for fingerprint)
 * @param senderKeyInfo - The sender's SSH key info (for fingerprint)
 * @param projectId - The project ID (for HKDF domain separation)
 * @returns The raw project key bytes
 */
export function openInviteBlob(
  blob: Uint8Array,
  recipientEd25519Sk: Uint8Array,
  recipientKeyInfo: SSHKeyInfo,
  senderKeyInfo: SSHKeyInfo,
  projectId: string,
): Uint8Array {
  // Parse the blob
  let offset = 0;
  const ephPk = blob.slice(offset, offset + 32); offset += 32;
  const nonce = blob.slice(offset, offset + 24); offset += 24;
  const tagStart = blob.length - 16;
  const ciphertext = blob.slice(offset, tagStart);
  const tag = blob.slice(tagStart);

  // Convert recipient Ed25519 secret key to X25519
  const recipientX25519Sk = ed25519ToX25519SecretKey(recipientEd25519Sk);

  // ECDH: shared_secret = X25519(recipient_x25519_secret, ephemeral_public)
  const sharedSecret = Buffer.alloc(sodium.crypto_scalarmult_BYTES);
  sodium.crypto_scalarmult(sharedSecret, Buffer.from(recipientX25519Sk), Buffer.from(ephPk));

  // Derive same encryption key
  const info = buildInviteHkdfInfo(senderKeyInfo.fingerprint, recipientKeyInfo.fingerprint, projectId);
  const encryptionKey = deriveKey(new Uint8Array(sharedSecret), info);

  // Decrypt
  const emptyAAD = new Uint8Array(0);
  const padded = aeadDecrypt(encryptionKey, nonce, ciphertext, tag, emptyAAD);

  // Zero sensitive buffers
  sharedSecret.fill(0);
  encryptionKey.fill(0);

  // Unpad and extract project key
  const payload = unpadPayload(padded);
  const parsed = JSON.parse(new TextDecoder().decode(payload));
  return Buffer.from(parsed.projectKey, 'base64');
}

/**
 * Build the HKDF info string with domain separation.
 *
 * Format: "chaoskb-invite-v1" || SHA256(senderFingerprint)(32) || SHA256(recipientFingerprint)(32) || SHA256(projectId)(32)
 * Fixed-width encoding prevents ambiguity from variable-length fields.
 */
function buildInviteHkdfInfo(senderFingerprint: string, recipientFingerprint: string, projectId: string): string {
  const senderHash = createHash('sha256').update(senderFingerprint).digest('hex').slice(0, 64);
  const recipientHash = createHash('sha256').update(recipientFingerprint).digest('hex').slice(0, 64);
  const projectHash = createHash('sha256').update(projectId).digest('hex').slice(0, 64);
  return `chaoskb-invite-v1${senderHash}${recipientHash}${projectHash}`;
}

/**
 * Pad payload to a fixed size to prevent metadata leakage from blob sizes.
 */
export function padPayload(payload: Uint8Array, targetSize: number): Uint8Array {
  if (payload.length > targetSize - 4) {
    throw new Error(`Payload too large to pad: ${payload.length} bytes (max ${targetSize - 4})`);
  }

  const padded = new Uint8Array(targetSize);
  // First 4 bytes: big-endian payload length
  const view = new DataView(padded.buffer);
  view.setUint32(0, payload.length, false);
  padded.set(payload, 4);

  // Fill remainder with random bytes
  const randomPadding = randomBytes(targetSize - 4 - payload.length);
  padded.set(randomPadding, 4 + payload.length);

  return padded;
}

/**
 * Remove padding to recover the original payload.
 */
export function unpadPayload(padded: Uint8Array): Uint8Array {
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const length = view.getUint32(0, false);

  if (length > padded.length - 4) {
    throw new Error('Invalid padding: declared length exceeds buffer');
  }

  return padded.slice(4, 4 + length);
}
