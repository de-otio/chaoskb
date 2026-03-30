# Tier Upgrade Protocol

Describes the cryptographic protocol for upgrading the security tier of an existing ChaosKB installation. Tier upgrades are irreversible downgrade paths are deliberately omitted.

---

## Background

ChaosKB has three security tiers (see [crypto.md](crypto.md) for full definitions):

| Tier         | Master key storage                          | Recovery factor(s)             |
|--------------|---------------------------------------------|--------------------------------|
| **Standard** | OS keyring (plaintext under keyring ACLs)   | SSH private key (server-stored wrapped copy) |
| **Enhanced** | OS keyring + BIP39 mnemonic paper backup    | BIP39 mnemonic OR SSH private key |
| **Maximum**  | Argon2id-derived from passphrase at runtime | Passphrase only                |

The *master key* is a 256-bit random key generated once at bootstrap. All data encryption keys are derived from it. Tier upgrades never re-encrypt existing data — they only change how the master key itself is protected.

---

## Invariants

1. The master key is never written to disk in plaintext (except during the upgrade window while it is held in memory).
2. A tier upgrade is atomic from the user's perspective: the new protection is written before the old protection is removed.
3. After a successful upgrade, `config.json::securityTier` is updated to reflect the new tier.
4. Tier upgrades are monotonically increasing: Standard → Enhanced → Maximum. Downgrading requires reinstall.

---

## Standard → Enhanced

### Goal

Add a BIP39 mnemonic as a second, offline recovery factor. The OS keyring copy remains as the primary operational key.

### Protocol

```
1. Retrieve master key from OS keyring
      masterKey = keyring.retrieve('chaoskb', 'master-key')

2. Encode as BIP39 24-word mnemonic
      mnemonic = bip39.entropyToMnemonic(masterKey)
      // masterKey must be exactly 32 bytes (256 bits) → 24 words

3. Display mnemonic to user
      print("Write down these 24 words and store them safely:")
      print(mnemonic)

4. Confirm user has recorded it (spot-check)
      Ask user to enter words at positions [i, j, k] (randomly chosen)
      Verify against mnemonic

5. Update config.json
      config.securityTier = 'enhanced'
      write(configPath, JSON.stringify(config, null, 2), { mode: 0o600 })

6. Done — no keyring changes needed
      The master key stays in the keyring unchanged.
      The mnemonic is the new recovery path; it is NOT stored anywhere by the app.
```

### Security properties

- The mnemonic directly encodes the master key (BIP39 entropy → mnemonic is reversible).
- The mnemonic is printed to stdout once and never stored. If the user loses it, they fall back to SSH key recovery (same as Standard tier).
- No data is re-encrypted. The keyring entry is unchanged.
- The server-stored SSH-wrapped copy of the master key is unchanged.

### Recovery from mnemonic (new device)

```
masterKey = bip39.mnemonicToEntropy(mnemonic)
keyring.store('chaoskb', 'master-key', masterKey)
```

---

## Standard → Maximum

### Goal

Replace OS-keyring storage with Argon2id-derived key protection. The master key is re-wrapped under the user's passphrase. No OS keyring dependency; no server-stored wrapped copy.

### Protocol

```
1. Check stdin.isTTY — error if not interactive
      Maximum tier requires passphrase entry; cannot proceed headlessly.

2. Retrieve master key from OS keyring
      masterKey = keyring.retrieve('chaoskb', 'master-key')

3. Prompt for passphrase (twice, must match)
      Enforce: min 5 words OR 25 characters, zxcvbn score ≥ 3

4. Generate Argon2id salt (CSPRNG, 16 bytes)
      salt = crypto.randomBytes(16)

5. Derive wrapping key from passphrase
      wrappingKey = argon2id(passphrase, salt, { t: 3, m: 65536, p: 1 })
      // Produces 32-byte wrapping key

6. Encrypt master key with wrapping key
      nonce = crypto.randomBytes(24)
      encryptedMasterKey = xchacha20poly1305.seal(wrappingKey, nonce, masterKey)

7. Write wrapped key blob to disk
      blob = { v: 1, kdf: 'argon2id', t: 3, m: 65536, p: 1,
               salt: salt.toString('hex'),
               nonce: nonce.toString('hex'),
               ciphertext: encryptedMasterKey.toString('hex') }
      write('~/.chaoskb/master-key.enc', JSON.stringify(blob), { mode: 0o600 })

8. Remove master key from OS keyring
      keyring.delete('chaoskb', 'master-key')

9. Update config.json
      config.securityTier = 'maximum'
      write(configPath, JSON.stringify(config, null, 2), { mode: 0o600 })

10. Wipe master key from memory
       masterKey.dispose()
       wrappingKey.dispose()
```

Steps 7 and 8 MUST execute in that order. Write the new protection before removing the old.

### Security properties

- No master key material in the OS keyring after upgrade.
- No server-stored wrapped copy (delete the SSH-wrapped entry from the server, or document that it becomes inert because the key material no longer matches).
- The `master-key.enc` blob is safe to back up — it is useless without the passphrase.
- Argon2id parameters exceed OWASP 2023 minimum by 3.3× memory, 1.5× iterations.

### Unlock on subsequent launches

```
blob = read('~/.chaoskb/master-key.enc')
passphrase = prompt("Enter your ChaosKB passphrase:")
wrappingKey = argon2id(passphrase, blob.salt, { t: blob.t, m: blob.m, p: blob.p })
masterKey = xchacha20poly1305.open(wrappingKey, blob.nonce, blob.ciphertext)
// masterKey held in memory for session duration
```

### Error path: incorrect passphrase

Argon2id + XChaCha20-Poly1305 provides authenticated encryption. A wrong passphrase produces a decryption error (tag mismatch). Print "Incorrect passphrase" and exit — do not retry in a loop (brute-force prevention is the user's responsibility at this tier).

---

## Enhanced → Maximum

Follows the same protocol as Standard → Maximum with one addition: before step 8, instruct the user that their BIP39 mnemonic is no longer a valid recovery path (since the master key is now passphrase-derived, not keyring-stored). The mnemonic is dead and can be destroyed.

```
print("Your 24-word recovery key is no longer valid after this upgrade.")
print("You may safely destroy it. Your passphrase is now your only recovery factor.")
```

---

## Blob format versioning

The `master-key.enc` file uses a `v` field to support future format changes:

```json
{
  "v": 1,
  "kdf": "argon2id",
  "t": 3,
  "m": 65536,
  "p": 1,
  "salt": "<hex>",
  "nonce": "<hex>",
  "ciphertext": "<hex>"
}
```

Future versions may change KDF parameters or switch algorithms. The unlock logic should dispatch on `v` and `kdf`. The current implementation only needs to handle `v: 1`.

---

## `config upgrade-tier` CLI command

```
chaoskb config upgrade-tier <enhanced|maximum>
```

Behavior:

- Reads current `securityTier` from `config.json`
- Errors if current tier >= requested tier ("Already at `<tier>` or higher")
- Requires interactive terminal for `maximum`
- Follows the protocol above
- Prints success confirmation to stdout

Implementation path: `src/cli/commands/config.ts`

---

## What is NOT changed by a tier upgrade

- Existing encrypted data blobs in `~/.chaoskb/local.db`
- Data encryption keys (derived from the master key at runtime)
- The derivation algorithm (`EncryptionService.deriveKeys`)

The master key is the root of trust. Upgrading the tier changes only how the master key is protected at rest, not how it is used to encrypt data.
