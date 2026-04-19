/**
 * SSH key helpers — thin re-exports over `@de-otio/keyring`'s
 * canonical implementations. Kept so existing chaoskb imports
 * (`parseSSHPublicKey`, `ed25519ToX25519*`) continue to work.
 *
 * New code should import directly from `@de-otio/keyring`.
 */
import {
  parseSshPublicKey,
  sshFingerprint,
  ed25519ToX25519PublicKey as kED25519ToX25519PublicKey,
  ed25519ToX25519SecretKey as kED25519ToX25519SecretKey,
  type SshKeyType,
  type SshPublicKey,
} from '@de-otio/keyring';
import type { SSHKeyInfo, SSHKeyType } from './types.js';

/** Back-compat alias for `parseSshPublicKey`. */
export function parseSSHPublicKey(keyString: string): SSHKeyInfo {
  const parsed: SshPublicKey = parseSshPublicKey(keyString);
  return {
    type: parsed.type as SSHKeyType,
    publicKeyBytes: parsed.publicKeyBytes,
    fingerprint: parsed.fingerprint,
    ...(parsed.comment !== undefined && { comment: parsed.comment }),
  };
}

export { sshFingerprint };
export type { SshKeyType };

/** Convert an Ed25519 public key to X25519 (Curve25519). */
export function ed25519ToX25519PublicKey(ed25519PublicKey: Uint8Array): Uint8Array {
  return kED25519ToX25519PublicKey(ed25519PublicKey);
}

/**
 * Convert an Ed25519 secret key to X25519 secret key.
 *
 * Note: keyring's canonical implementation returns an `ISecureBuffer`
 * (design-review B5 fix). For back-compat with the old chaoskb signature
 * we copy the bytes into a plain `Uint8Array` and dispose the secure
 * handle. Callers that want the secure-buffer form should import from
 * `@de-otio/keyring` directly.
 */
export function ed25519ToX25519SecretKey(ed25519SecretKey: Uint8Array): Uint8Array {
  const secure = kED25519ToX25519SecretKey(ed25519SecretKey);
  try {
    return new Uint8Array(Buffer.from(secure.buffer));
  } finally {
    secure.dispose();
  }
}
