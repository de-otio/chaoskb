/**
 * chaoskb crypto module — knowledge-base blob primitives.
 *
 * Key-lifecycle (master-key wrapping, tiers, project keys, invites,
 * TOFU pinning) lives in `@de-otio/keyring`. Pre-existing re-exports
 * of those modules have been removed.
 */
export * from './types.js';
export { SecureBuffer } from '@de-otio/crypto-envelope';
export { canonicalJson } from './canonical-json.js';
export { generateBlobId } from './blob-id.js';
export { aeadEncrypt, aeadDecrypt } from './aead.js';
export { deriveKey, deriveKeySet } from './hkdf.js';
export { deriveFromPassphrase as argon2Derive } from '@de-otio/crypto-envelope/primitives';
export { constructAAD } from './aad.js';
export { computeCommitment, verifyCommitment } from './commitment.js';
export { encryptPayload, decryptEnvelope } from './envelope.js';
export { parseSSHPublicKey, ed25519ToX25519PublicKey, ed25519ToX25519SecretKey } from './ssh-keys.js';
export { EncryptionService } from './encryption-service.js';
