// Types shared with `@de-otio/crypto-envelope` are re-exported below; types
// unique to chaoskb (payload variants, SSH info, encryption-service
// interface) are declared here.

import type {
  Algorithm as _Algorithm,
  AnyEnvelope as _AnyEnvelope,
  EnvelopeV1 as _EnvelopeV1,
  EnvelopeV2 as _EnvelopeV2,
  ISecureBuffer as _ISecureBuffer,
} from '@de-otio/crypto-envelope';

export type ISecureBuffer = _ISecureBuffer;
export type Algorithm = _Algorithm;
export type EnvelopeV2 = _EnvelopeV2;
export type AnyEnvelope = _AnyEnvelope;

/** Envelope wire type (v1). Alias of the package's `EnvelopeV1` — same
 *  shape, kept under the historical chaoskb name. */
export type Envelope = _EnvelopeV1;

// ── chaoskb-specific types ─────────────────────────────────────────────

/** Key identifier for derived keys. chaoskb-specific vocabulary. */
export type KeyId = 'CEK' | 'MEK' | 'EEK';

/** Security tier for key management */
export enum SecurityTier {
  /** SSH key wrapping (crypto_box_seal for Ed25519, RSA-OAEP KEM+DEM for RSA) */
  Standard = 'standard',
  /** @deprecated BIP39 24-word recovery key + SSH key. Use Standard or Maximum instead. */
  Enhanced = 'enhanced',
  /** Argon2id passphrase derivation, no recovery */
  Maximum = 'maximum',
}

/** Set of derived keys from the master key */
export interface DerivedKeySet {
  /** Content encryption key (HKDF info: "chaoskb-content") */
  contentKey: ISecureBuffer;
  /** Metadata encryption key (HKDF info: "chaoskb-metadata") */
  metadataKey: ISecureBuffer;
  /** Embedding encryption key (HKDF info: "chaoskb-embedding", reserved) */
  embeddingKey: ISecureBuffer;
  /** Commitment key for HMAC (HKDF info: "chaoskb-commit") */
  commitKey: ISecureBuffer;
}

/** SSH key type */
export type SSHKeyType = 'ed25519' | 'rsa';

/** Parsed SSH key information — chaoskb-local shape (kept for back-compat;
 *  new code should use `SshPublicKey` from `@de-otio/keyring`). */
export interface SSHKeyInfo {
  type: SSHKeyType;
  publicKeyBytes: Uint8Array;
  fingerprint: string;
  comment?: string;
}

/** Plaintext payload types */
export type PayloadType = 'source' | 'chunk' | 'canary';

/** Source payload (decrypted) */
export interface SourcePayload {
  type: 'source';
  url: string;
  title?: string;
  tags?: string[];
  chunkCount: number;
  chunkIds: string[];
}

/** Chunk payload (decrypted) */
export interface ChunkPayload {
  type: 'chunk';
  sourceId: string;
  index: number;
  model: string;
  content: string;
  tokenCount: number;
  embedding: number[];
}

/** Canary payload for key verification */
export interface CanaryPayload {
  type: 'canary';
  value: 'chaoskb-canary-v1';
}

/** Any decrypted payload */
export type Payload = SourcePayload | ChunkPayload | CanaryPayload;

/** Result of encryption */
export interface EncryptResult {
  envelope: Envelope;
  /** Raw JSON bytes for upload */
  bytes: Uint8Array;
}

/** Result of decryption */
export interface DecryptResult {
  payload: Payload;
  envelope: Envelope;
}

/**
 * Encryption service interface — used by sync/canary and the MCP server.
 *
 * The default implementation {@link EncryptionService} delegates to
 * `@de-otio/crypto-envelope`'s `encryptV1` / `decryptV1` primitives and
 * chaoskb's HKDF key-set derivation. Tests provide their own mocks.
 */
export interface IEncryptionService {
  /** Generate a new random master key */
  generateMasterKey(): ISecureBuffer;
  /** Derive all subkeys from master key */
  deriveKeys(masterKey: ISecureBuffer, salt?: Uint8Array): DerivedKeySet;
  /** Encrypt a payload into an envelope */
  encrypt(payload: Payload, keys: DerivedKeySet, kid?: KeyId): EncryptResult;
  /** Decrypt an envelope into a payload */
  decrypt(envelope: Envelope, keys: DerivedKeySet): DecryptResult;
  /** Generate a blob ID */
  generateBlobId(): string;
}
