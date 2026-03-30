import * as fs from 'node:fs';
import * as readline from 'node:readline';
import { randomBytes } from 'node:crypto';
import { loadConfig, saveConfig, CHAOSKB_DIR } from './setup.js';
import { SecurityTier } from '../../crypto/types.js';
import * as path from 'node:path';

const TIER_ORDER: SecurityTier[] = [SecurityTier.Standard, SecurityTier.Enhanced, SecurityTier.Maximum];

function tierIndex(tier: string): number {
  return TIER_ORDER.indexOf(tier as SecurityTier);
}

function prompt(rl: readline.Interface, question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
}

/**
 * Upgrade security tier.
 *
 * Standard → Enhanced: encode master key as BIP39 mnemonic, display to user.
 * Standard → Maximum: re-wrap master key under Argon2id-derived key from passphrase.
 * Enhanced → Maximum: same as above, with note that mnemonic is invalidated.
 */
export async function upgradeTierCommand(tier: string): Promise<void> {
  // Validate tier argument
  if (tier !== 'enhanced' && tier !== 'maximum') {
    console.error(`Invalid tier: "${tier}". Must be "enhanced" or "maximum".`);
    process.exitCode = 1;
    return;
  }

  const config = await loadConfig();
  if (!config) {
    console.error('ChaosKB is not configured. Run `chaoskb-mcp setup` first.');
    process.exitCode = 1;
    return;
  }

  const currentIndex = tierIndex(config.securityTier);
  const targetIndex = tierIndex(tier);

  if (targetIndex <= currentIndex) {
    console.error(`Already at "${config.securityTier}" tier or higher.`);
    process.exitCode = 1;
    return;
  }

  // Retrieve master key from OS keyring
  const { KeyringService } = await import('../../crypto/keyring.js');
  const keyring = new KeyringService();
  let masterKey = await keyring.retrieve('chaoskb', 'master-key');

  if (!masterKey) {
    // Try file-based key fallback
    if (process.env.CHAOSKB_KEY_STORAGE === 'file') {
      const { FILE_KEY_PATH } = await import('../bootstrap.js');
      try {
        const hex = fs.readFileSync(FILE_KEY_PATH, 'utf-8').trim();
        const { SecureBuffer } = await import('../../crypto/secure-buffer.js');
        masterKey = SecureBuffer.from(Buffer.from(hex, 'hex'));
      } catch {
        // Fall through to error
      }
    }
    if (!masterKey) {
      console.error('Master key not found. Ensure your OS keyring is accessible.');
      process.exitCode = 1;
      return;
    }
  }

  try {
    if (tier === 'enhanced') {
      await upgradeToEnhanced(masterKey, config);
    } else {
      await upgradeToMaximum(masterKey, config);
    }
  } finally {
    masterKey.dispose();
  }
}

async function upgradeToEnhanced(
  masterKey: import('../../crypto/types.js').ISecureBuffer,
  config: { securityTier: string; projects: Array<{ name: string; createdAt: string }> },
): Promise<void> {
  const { generateRecoveryKey } = await import('../../crypto/tiers/enhanced.js');

  const mnemonic = generateRecoveryKey(masterKey);
  const words = mnemonic.split(' ');

  console.log('');
  console.log('Your 24-word recovery key:');
  console.log('');
  // Display in 3 columns of 8
  for (let i = 0; i < 24; i += 3) {
    const cols = [];
    for (let j = 0; j < 3 && i + j < 24; j++) {
      cols.push(`  ${String(i + j + 1).padStart(2, ' ')}. ${words[i + j].padEnd(10)}`);
    }
    console.log(cols.join(''));
  }
  console.log('');
  console.log('Write these words down and store them safely.');
  console.log('This is your backup recovery factor. Do NOT store it digitally.');
  console.log('');

  // Spot-check: ask user to confirm 2 random words
  const indices = pickRandomIndices(24, 2);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    for (const idx of indices) {
      const answer = await prompt(rl, `Confirm word #${idx + 1}: `);
      if (answer.toLowerCase() !== words[idx].toLowerCase()) {
        console.error(`Incorrect. Expected word #${idx + 1} to be "${words[idx]}".`);
        console.error('Tier upgrade cancelled.');
        process.exitCode = 1;
        return;
      }
    }
  } finally {
    rl.close();
  }

  // Update config
  config.securityTier = SecurityTier.Enhanced;
  await saveConfig(config);

  console.log('');
  console.log('Security tier upgraded to Enhanced.');
  console.log('Your master key remains in the OS keyring. The recovery key is your backup.');
}

async function upgradeToMaximum(
  masterKey: import('../../crypto/types.js').ISecureBuffer,
  config: { securityTier: string; projects: Array<{ name: string; createdAt: string }> },
): Promise<void> {
  if (!process.stdin.isTTY) {
    console.error('Maximum tier requires an interactive terminal for passphrase entry.');
    process.exitCode = 1;
    return;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  let passphrase: string;
  try {
    passphrase = await prompt(rl, 'Enter new passphrase (min 8 characters): ');
    if (passphrase.length < 8) {
      console.error('Passphrase must be at least 8 characters.');
      process.exitCode = 1;
      return;
    }

    const confirm = await prompt(rl, 'Confirm passphrase: ');
    if (passphrase !== confirm) {
      console.error('Passphrases do not match.');
      process.exitCode = 1;
      return;
    }

    if (config.securityTier === SecurityTier.Enhanced) {
      console.log('');
      console.log('Note: Your 24-word recovery key will no longer be valid after this upgrade.');
      console.log('Your passphrase becomes your only recovery factor.');
      console.log('');
    }
  } finally {
    rl.close();
  }

  console.log('Deriving key with Argon2id (this may take a moment)...');

  // Generate salt and derive wrapping key
  const salt = randomBytes(16);
  const { argon2Derive } = await import('../../crypto/index.js');
  const wrappingKey = argon2Derive(passphrase, salt);

  try {
    // Encrypt master key with wrapping key using XChaCha20-Poly1305
    const { aeadEncrypt } = await import('../../crypto/aead.js');
    const aad = Buffer.from('chaoskb-master-key-wrap-v1');
    const result = aeadEncrypt(
      wrappingKey.buffer,
      masterKey.buffer,
      aad,
    );

    // Write encrypted key blob
    const blob = {
      v: 1,
      kdf: 'argon2id',
      t: 3,
      m: 65536,
      p: 1,
      salt: Buffer.from(salt).toString('hex'),
      nonce: Buffer.from(result.nonce).toString('hex'),
      ciphertext: Buffer.from(new Uint8Array([...result.ciphertext, ...result.tag])).toString('hex'),
    };

    const blobPath = path.join(CHAOSKB_DIR, 'master-key.enc');
    // Step 7: write new protection BEFORE removing old
    fs.writeFileSync(blobPath, JSON.stringify(blob, null, 2), { mode: 0o600 });

    // Step 8: remove master key from OS keyring
    const { KeyringService } = await import('../../crypto/keyring.js');
    const keyring = new KeyringService();
    await keyring.delete('chaoskb', 'master-key');

    // Also remove file-based key if it exists
    const { FILE_KEY_PATH } = await import('../bootstrap.js');
    try {
      fs.unlinkSync(FILE_KEY_PATH);
    } catch {
      // File may not exist
    }

    // Update config
    config.securityTier = SecurityTier.Maximum;
    await saveConfig(config);

    console.log('');
    console.log('Security tier upgraded to Maximum.');
    console.log(`Encrypted key written to ${blobPath}`);
    console.log('Your passphrase is now your only recovery factor.');
  } finally {
    wrappingKey.dispose();
  }
}

function pickRandomIndices(max: number, count: number): number[] {
  const indices = new Set<number>();
  while (indices.size < count) {
    indices.add(Math.floor(Math.random() * max));
  }
  return [...indices].sort((a, b) => a - b);
}
