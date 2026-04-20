import { SecureBuffer } from '@de-otio/crypto-envelope';
import { deriveKey } from '@de-otio/crypto-envelope/primitives';

import type { DerivedKeySet } from './types.js';

// Re-export `deriveKey` so callers that import it from this module keep working.
export { deriveKey };

/**
 * Derive the four chaoskb subkeys from a master key via HKDF-SHA256.
 *
 * Info strings are chaoskb-specific and MUST NOT change — every encrypted
 * blob on disk was bound to these labels at encrypt time, and changing them
 * would mean no existing envelope could decrypt.
 */
export function deriveKeySet(masterKey: Uint8Array, salt?: Uint8Array): DerivedKeySet {
  const cekBytes = deriveKey(masterKey, 'chaoskb-content', salt);
  const mekBytes = deriveKey(masterKey, 'chaoskb-metadata', salt);
  const eekBytes = deriveKey(masterKey, 'chaoskb-embedding', salt);
  const ckyBytes = deriveKey(masterKey, 'chaoskb-commit', salt);

  return {
    contentKey: SecureBuffer.from(Buffer.from(cekBytes)),
    metadataKey: SecureBuffer.from(Buffer.from(mekBytes)),
    embeddingKey: SecureBuffer.from(Buffer.from(eekBytes)),
    commitKey: SecureBuffer.from(Buffer.from(ckyBytes)),
  };
}
