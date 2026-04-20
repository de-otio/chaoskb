/**
 * XChaCha20-Poly1305 AEAD primitives.
 *
 * Thin back-compat wrapper around `@de-otio/crypto-envelope/primitives`.
 * The package's 0.2 signature takes an explicit `alg` parameter; chaoskb
 * only uses XChaCha20-Poly1305 at these call sites, so we keep the
 * pre-0.2 call shape locally and inject the algorithm constant here.
 */
import {
  aeadEncrypt as envAeadEncrypt,
  aeadDecrypt as envAeadDecrypt,
  type AeadResult,
} from '@de-otio/crypto-envelope/primitives';

const ALG = 'XChaCha20-Poly1305' as const;

export type { AeadResult };

export function aeadEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): AeadResult {
  return envAeadEncrypt(ALG, key, plaintext, aad);
}

export function aeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  return envAeadDecrypt(ALG, key, nonce, ciphertext, tag, aad);
}
