import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { loadConfig, saveConfig } from './setup.js';

/**
 * CLI command: chaoskb-mcp config rotate-key --new-key <path>
 *
 * Performs Phase 1 of two-phase key rotation:
 * 1. Reads current config to get endpoint and current key fingerprint
 * 2. Detects the new SSH key from --new-key path (or auto-detects)
 * 3. Retrieves master key from keyring
 * 4. Re-wraps master key with the new SSH public key
 * 5. Calls POST /v1/rotate-start with { newPublicKey, wrappedBlob }
 * 6. Uploads new wrapped blob to /v1/wrapped-key
 * 7. Updates config with new key fingerprint and keyPath
 */
export async function rotateKeyCommand(newKeyPath?: string): Promise<void> {
  const config = await loadConfig();
  if (!config) {
    console.error('ChaosKB is not configured. Run `chaoskb-mcp setup` first.');
    process.exitCode = 1;
    return;
  }

  if (!config.endpoint) {
    console.error('Sync is not configured. Key rotation requires an active sync endpoint.');
    process.exitCode = 1;
    return;
  }

  if (!config.sshKeyFingerprint) {
    console.error('No SSH key configured. Run `chaoskb-mcp setup-sync` first.');
    process.exitCode = 1;
    return;
  }

  // Detect the new SSH key
  const newKeyInfo = await detectNewSSHKey(newKeyPath);
  if (!newKeyInfo) {
    console.error(
      'Could not detect a new SSH key.' +
      (newKeyPath ? ` File not found: ${newKeyPath}` : ' Specify --new-key <path>.'),
    );
    process.exitCode = 1;
    return;
  }

  // Verify the new key is different from the current one
  if (newKeyInfo.fingerprint === config.sshKeyFingerprint) {
    console.error('The new key is the same as the current key. Nothing to rotate.');
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
    // Re-wrap master key with the new SSH public key
    const { parseSSHPublicKey } = await import('../../crypto/ssh-keys.js');
    const { wrapMasterKey } = await import('../../crypto/tiers/standard.js');

    const sshKeyInfo = parseSSHPublicKey(newKeyInfo.publicKeyLine);
    const wrappedBlob = wrapMasterKey(masterKey, sshKeyInfo);
    const wrappedBlobBase64 = Buffer.from(wrappedBlob).toString('base64');

    // Extract the base64 key blob from the public key line
    const pubKeyParts = newKeyInfo.publicKeyLine.trim().split(/\s+/);
    const newPublicKeyBase64 = pubKeyParts.length >= 2 ? pubKeyParts[1] : pubKeyParts[0];

    // Call POST /v1/rotate-start with the old key for auth
    const { SSHSigner } = await import('../../sync/ssh-signer.js');
    const { SequenceCounter } = await import('../../sync/sequence.js');

    const oldSigner = new SSHSigner(config.sshKeyPath ?? undefined);
    const sequence = new SequenceCounter();

    const body = JSON.stringify({ newPublicKey: newPublicKeyBase64, wrappedBlob: wrappedBlobBase64 });
    const bodyBytes = new TextEncoder().encode(body);

    const seq = sequence.next();
    const authResult = await oldSigner.signRequest('POST', '/v1/rotate-start', seq, bodyBytes);

    const endpoint = config.endpoint.replace(/\/+$/, '');

    const rotateResponse = await fetch(`${endpoint}/v1/rotate-start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: authResult.authorization,
        'X-ChaosKB-Timestamp': authResult.timestamp,
        'X-ChaosKB-Sequence': String(authResult.sequence),
        'X-ChaosKB-PublicKey': authResult.publicKey,
      },
      body,
    });

    if (!rotateResponse.ok) {
      const errBody = await rotateResponse.text();
      console.error(`Failed to start key rotation: ${rotateResponse.status} ${errBody}`);
      process.exitCode = 1;
      return;
    }

    // Upload new wrapped blob to /v1/wrapped-key using the NEW key for auth
    const newSigner = new SSHSigner(newKeyInfo.keyPath);
    const seq2 = sequence.next();
    const uploadAuth = await newSigner.signRequest('PUT', '/v1/wrapped-key', seq2, wrappedBlob);

    const uploadResponse = await fetch(`${endpoint}/v1/wrapped-key`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/octet-stream',
        Authorization: uploadAuth.authorization,
        'X-ChaosKB-Timestamp': uploadAuth.timestamp,
        'X-ChaosKB-Sequence': String(uploadAuth.sequence),
        'X-ChaosKB-PublicKey': uploadAuth.publicKey,
      },
      body: wrappedBlob,
    });

    if (!uploadResponse.ok) {
      const errBody = await uploadResponse.text();
      console.error(`Failed to upload wrapped key: ${uploadResponse.status} ${errBody}`);
      process.exitCode = 1;
      return;
    }

    // Update config with new key fingerprint and keyPath
    config.sshKeyFingerprint = newKeyInfo.fingerprint;
    config.sshKeyPath = newKeyInfo.keyPath;
    await saveConfig(config);

    console.log('Key rotation started. Other devices will be notified on next sync.');
  } finally {
    masterKey.dispose();
  }
}

// --- SSH key detection ---

interface NewSSHKeyInfo {
  publicKeyLine: string;
  fingerprint: string;
  keyPath: string;
}

/**
 * Detect the new SSH key to rotate to.
 *
 * If newKeyPath is provided, reads that key file.
 * Otherwise, auto-detects from common SSH key locations, preferring
 * keys that are NOT the currently configured key.
 */
async function detectNewSSHKey(newKeyPath?: string): Promise<NewSSHKeyInfo | null> {
  if (newKeyPath) {
    return readSSHKeyFromPath(newKeyPath);
  }

  // Auto-detect: try common locations
  const sshDir = path.join(os.homedir(), '.ssh');
  const candidates = [
    { file: 'id_ed25519.pub', keyFile: 'id_ed25519' },
    { file: 'id_rsa.pub', keyFile: 'id_rsa' },
  ];

  for (const { file, keyFile } of candidates) {
    const pubKeyPath = path.join(sshDir, file);
    if (fs.existsSync(pubKeyPath)) {
      const result = await readSSHKeyFromPath(path.join(sshDir, keyFile));
      if (result) return result;
    }
  }

  return null;
}

async function readSSHKeyFromPath(keyPath: string): Promise<NewSSHKeyInfo | null> {
  const pubKeyPath = keyPath.endsWith('.pub') ? keyPath : keyPath + '.pub';
  const privateKeyPath = keyPath.endsWith('.pub') ? keyPath.slice(0, -4) : keyPath;

  try {
    const content = fs.readFileSync(pubKeyPath, 'utf-8').trim();
    const { parseSSHPublicKey } = await import('../../crypto/ssh-keys.js');
    const parsed = parseSSHPublicKey(content);
    return {
      publicKeyLine: content,
      fingerprint: parsed.fingerprint,
      keyPath: privateKeyPath,
    };
  } catch {
    return null;
  }
}
