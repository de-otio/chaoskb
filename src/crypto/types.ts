/**
 * Memory-locked buffer for sensitive key material.
 * Wraps sodium_malloc() with mlock and auto-zeroing on dispose.
 */
export interface ISecureBuffer {
  /** Read the buffer contents. Throws if disposed. */
  readonly buffer: Buffer;
  /** Byte length of the buffer */
  readonly length: number;
  /** Whether the buffer has been zeroed and disposed */
  readonly isDisposed: boolean;
  /** Zero the buffer contents and release memory */
  dispose(): void;
}

/** Supported encryption algorithms */
export type Algorithm = 'XChaCha20-Poly1305' | 'AES-256-GCM';

/** Key identifier for derived keys */
export type KeyId = 'CEK' | 'MEK' | 'EEK';

/** Security tier for key management */
export enum SecurityTier {
  /** SSH key wrapping (crypto_box_seal for Ed25519, RSA-OAEP KEM+DEM for RSA) */
  Standard = 'standard',
  /** BIP39 24-word recovery key + SSH key */
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

/** Parsed SSH key information */
export interface SSHKeyInfo {
  type: SSHKeyType;
  publicKeyBytes: Uint8Array;
  fingerprint: string;
  comment?: string;
}

/** Encryption envelope v1 wire format */
export interface Envelope {
  /** Envelope version (must be 1) */
  v: 1;
  /** Opaque blob identifier (b_ prefix + base62) */
  id: string;
  /** ISO 8601 timestamp (server-generated) */
  ts: string;
  /** Encryption envelope */
  enc: {
    /** Algorithm identifier */
    alg: Algorithm;
    /** Key identifier */
    kid: KeyId;
    /** Base64-encoded: nonce || ciphertext || auth_tag */
    ct: string;
    /** Byte length of decoded ct */
    'ct.len': number;
    /** Base64-encoded HMAC-SHA256 key commitment */
    commit: string;
  };
}

/**
 * Envelope v2 CBOR wire format — stores ct and commit as raw binary
 * instead of base64, saving ~33% size on ciphertext.
 */
export interface EnvelopeV2 {
  /** Envelope version (must be 2) */
  v: 2;
  /** Opaque blob identifier */
  id: string;
  /** ISO 8601 timestamp */
  ts: string;
  /** Encryption envelope */
  enc: {
    alg: Algorithm;
    kid: KeyId;
    /** Raw binary: nonce || ciphertext || auth_tag */
    ct: Uint8Array;
    /** HMAC-SHA256 key commitment (raw binary) */
    commit: Uint8Array;
  };
}

/** Union type for any supported envelope version */
export type AnyEnvelope = Envelope | EnvelopeV2;

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

/** OS keyring service interface */
export interface IKeyringService {
  store(service: string, account: string, secret: ISecureBuffer): Promise<void>;
  retrieve(service: string, account: string): Promise<ISecureBuffer | null>;
  delete(service: string, account: string): Promise<boolean>;
}

/** Encryption service interface */
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

/** Key management service for a specific security tier */
export interface IKeyManager {
  tier: SecurityTier;
  /** Wrap master key for storage */
  wrapMasterKey(masterKey: ISecureBuffer): Promise<Uint8Array>;
  /** Unwrap master key from storage */
  unwrapMasterKey(wrappedKey: Uint8Array): Promise<ISecureBuffer>;
}

/** Project key management */
export interface IProjectKeyManager {
  /** Generate a new project key and wrap with personal master key */
  createProjectKey(
    masterKey: ISecureBuffer,
  ): Promise<{ projectKey: ISecureBuffer; wrappedKey: Uint8Array }>;
  /** Unwrap a project key using personal master key */
  unwrapProjectKey(wrappedKey: Uint8Array, masterKey: ISecureBuffer): Promise<ISecureBuffer>;
}
