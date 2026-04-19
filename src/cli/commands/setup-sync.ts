import * as readline from 'node:readline';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadConfig, saveConfig } from './setup.js';
import { SSHSigner } from '../../sync/ssh-signer.js';
import { collectDeviceMetadata } from '../device-metadata.js';
import { detectGitHubUsername, matchGitHubKeys } from '../github.js';

function prompt(rl: readline.Interface, question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
}

export interface SetupSyncOptions {
  github?: string;
  githubAuto?: boolean;
}

export async function setupSyncCommand(options: SetupSyncOptions = {}): Promise<void> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    const config = await loadConfig();
    if (!config) {
      console.error('ChaosKB is not set up. Run `chaoskb-mcp setup` first.');
      process.exit(1);
    }

    console.log('');
    console.log('  ChaosKB Sync Setup');
    console.log('  ==================');
    console.log('');

    // 1. Prompt for server endpoint
    const endpoint = await prompt(rl, '  Server endpoint URL: ');

    if (!endpoint) {
      console.log('  No endpoint provided. Setup cancelled.');
      return;
    }

    // 2. Reject non-HTTPS endpoints
    if (!endpoint.startsWith('https://')) {
      console.error('');
      console.error('  Error: Only HTTPS endpoints are supported.');
      console.error('  The endpoint must start with https://');
      console.error('');
      process.exit(1);
    }

    // 3. Test connection
    console.log('');
    console.log('  Testing connection...');

    try {
      const healthUrl = new URL('/health', endpoint).href;
      const response = await fetch(healthUrl, {
        method: 'GET',
        signal: AbortSignal.timeout(10000),
      });

      if (!response.ok) {
        console.error(`  Server returned status ${response.status}. Check the endpoint and try again.`);
        process.exit(1);
      }
      console.log('  Connection successful.');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`  Connection failed: ${message}`);
      console.error('  Check the endpoint and try again.');
      process.exit(1);
    }

    // 4. Find SSH key
    const sshPubKeyPath = findSSHPublicKey();
    if (!sshPubKeyPath) {
      console.error('  No SSH public key found. Ensure you have ~/.ssh/id_ed25519.pub or ~/.ssh/id_rsa.pub');
      process.exit(1);
    }
    const sshKeyPath = sshPubKeyPath.replace('.pub', '');
    const signer = new SSHSigner(sshKeyPath);

    // 5. GitHub integration (optional)
    let githubUsername: string | undefined = options.github;

    if (options.githubAuto && !githubUsername) {
      console.log('');
      console.log('  Detecting GitHub account...');
      const detection = await detectGitHubUsername();
      if (detection.username) {
        // Verify the SSH key matches
        const matches = await matchGitHubKeys(detection.username);
        if (matches.length > 0) {
          const matchedKeyPath = matches[0].localKeyPath;
          console.log(`  Found GitHub account: ${detection.username}`);
          console.log(`  Matching SSH key: ${matchedKeyPath}`);
          githubUsername = detection.username;
        } else {
          console.log(`  GitHub account found (${detection.username}) but no SSH keys match.`);
          console.log('  Proceeding without GitHub linking.');
        }
      } else {
        console.log('  No GitHub account detected. Proceeding without GitHub linking.');
      }
    }

    if (githubUsername) {
      console.log(`  GitHub linking: ${githubUsername}`);
    }

    // 6. Get challenge from server
    console.log('');
    console.log('  Registering SSH public key...');

    let challengeNonce: string;
    try {
      const challengeUrl = new URL('/v1/register/challenge', endpoint).href;
      const challengeResp = await fetch(challengeUrl, {
        method: 'GET',
        signal: AbortSignal.timeout(10000),
      });
      if (!challengeResp.ok) {
        throw new Error(`Challenge request failed: ${challengeResp.status}`);
      }
      const challengeBody = await challengeResp.json() as { challenge: string };
      challengeNonce = challengeBody.challenge;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`  Failed to get registration challenge: ${message}`);
      process.exit(1);
    }

    // 7. Sign challenge and register
    const { signature, publicKey } = await signer.signRegistrationChallenge(challengeNonce);
    const deviceInfo = await collectDeviceMetadata();

    const registerBody: Record<string, unknown> = {
      publicKey,
      signedChallenge: signature,
      challengeNonce,
      deviceInfo,
    };
    if (githubUsername) {
      registerBody.github = githubUsername;
    }

    try {
      const registerUrl = new URL('/v1/auth/register', endpoint).href;
      const response = await fetch(registerUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(registerBody),
        signal: AbortSignal.timeout(10000),
      });

      const responseBody = await response.json() as Record<string, unknown>;

      if (response.status === 200 && responseBody.status === 'auto_linked') {
        console.log(`  Auto-linked via GitHub (${githubUsername}).`);
        console.log('  Waiting for existing device to share encryption key...');

        // Poll for wrapped master key from the existing device
        const wrappedKey = await pollForWrappedKey(endpoint, sshKeyPath);
        if (wrappedKey) {
          console.log('  Encryption key received.');
          // The wrapped key handling (unwrap + store in keyring) will be done
          // by the sync service on first sync. Save the blob for now.
          const wrappedKeyPath = path.join(os.homedir(), '.chaoskb', 'wrapped-key.bin');
          fs.mkdirSync(path.dirname(wrappedKeyPath), { recursive: true });
          fs.writeFileSync(wrappedKeyPath, Buffer.from(wrappedKey));
        } else {
          console.log('  Timed out waiting for encryption key.');
          console.log('  The key will sync automatically when your other device comes online.');
        }
      } else if (response.status === 201) {
        console.log('  SSH public key registered.');
      } else if (response.status === 400 && responseBody.error === 'github_verification_failed') {
        console.log('  GitHub verification failed. Registering without GitHub linking...');
        // Retry without GitHub
        delete registerBody.github;
        const retryResp = await fetch(new URL('/v1/auth/register', endpoint).href, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(registerBody),
          signal: AbortSignal.timeout(10000),
        });
        if (!retryResp.ok) {
          const retryBody = await retryResp.text();
          console.error(`  Registration failed (${retryResp.status}): ${retryBody}`);
          process.exit(1);
        }
        githubUsername = undefined;
        console.log('  SSH public key registered (without GitHub linking).');
      } else if (!response.ok) {
        console.error(`  Registration failed (${response.status}): ${JSON.stringify(responseBody)}`);
        process.exit(1);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`  Registration failed: ${message}`);
      process.exit(1);
    }

    // 8. Write config
    config.endpoint = endpoint;
    config.sshKeyPath = sshKeyPath;
    if (githubUsername) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (config as any).github = githubUsername;
    }
    await saveConfig(config);

    console.log('');
    console.log(`  Config saved to ~/.chaoskb/config.json`);

    // 9. Canary blob verification
    console.log('');
    console.log('  Running canary blob verification...');
    try {
      const { EncryptionService } = await import('../../crypto/encryption-service.js');
      const {
        KeyRing,
        StandardTier,
        OsKeychainStorage,
        FileSystemStorage,
      } = await import('@de-otio/keyring');
      const { SecureBuffer } = await import('@de-otio/crypto-envelope');
      const { KEYRING_SERVICE, CHAOSKB_DIR: _CDIR } = await import('../bootstrap.js');

      const storage = process.env.CHAOSKB_KEY_STORAGE === 'file'
        ? new FileSystemStorage<'standard'>({
            root: path.join(_CDIR, 'keyring'),
            acceptedTiers: ['standard'] as const,
          })
        : new OsKeychainStorage<'standard'>({
            service: KEYRING_SERVICE,
            acceptedTiers: ['standard'] as const,
          });
      const sshPubLine = fs.readFileSync(sshPubKeyPath, 'utf-8').trim();
      const sshPem = fs.readFileSync(sshKeyPath, 'utf-8');
      const tier = StandardTier.fromSshKey(sshPubLine);
      const ring = new KeyRing({ tier, storage });
      try {
        await ring.unlockWithSshKey(sshPem);
      } catch {
        console.error('  Master key not found. Run `chaoskb-mcp setup` first.');
        process.exit(1);
      }
      const masterKey = await ring.withMaster(async (master) =>
        SecureBuffer.from(Buffer.from(master.buffer)),
      );
      const encryption = new EncryptionService();
      const keys = encryption.deriveKeys(masterKey);
      const canary = encryption.encrypt(
        { type: 'canary', value: 'chaoskb-canary-v1' },
        keys,
      );
      // Upload canary
      const putUrl = new URL(`/v1/blobs/${canary.envelope.id}`, endpoint).href;
      const putResp = await fetch(putUrl, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: canary.bytes,
        signal: AbortSignal.timeout(10000),
      });
      if (!putResp.ok) {
        throw new Error(`Upload failed: ${putResp.status}`);
      }
      // Download and verify
      const getUrl = new URL(`/v1/blobs/${canary.envelope.id}`, endpoint).href;
      const getResp = await fetch(getUrl, { signal: AbortSignal.timeout(10000) });
      if (!getResp.ok) {
        throw new Error(`Download failed: ${getResp.status}`);
      }
      const downloaded = await getResp.arrayBuffer();
      const downloadedEnvelope = JSON.parse(new TextDecoder().decode(downloaded));
      const decrypted = encryption.decrypt(downloadedEnvelope, keys);
      if (decrypted.payload.type !== 'canary' || decrypted.payload.value !== 'chaoskb-canary-v1') {
        throw new Error('Canary payload mismatch');
      }
      masterKey.dispose();
      await ring.lock();
      console.log('  Canary verification passed.');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`  Canary verification failed: ${message}`);
      console.error('  Sync setup cancelled.');
      process.exit(1);
    }

    console.log('');
    console.log('  Sync setup complete!');
    console.log(`  Endpoint: ${endpoint}`);
    if (githubUsername) {
      console.log(`  GitHub: ${githubUsername}`);
    }
    console.log('');
  } finally {
    rl.close();
  }
}

/**
 * Poll the server for a wrapped master key after auto-linking.
 * The existing device wraps the master key for the new device's SSH key
 * and uploads it. We poll until it appears or timeout (5 minutes).
 */
async function pollForWrappedKey(
  endpoint: string,
  sshKeyPath: string,
): Promise<Uint8Array | null> {
  const { createSyncHttpClientFromConfig } = await import('../../sync/client-factory.js');
  const { DatabaseManager } = await import('../../storage/database-manager.js');
  const db = new DatabaseManager().getPersonalDb();
  const client = createSyncHttpClientFromConfig({ endpoint, sshKeyPath }, db.syncSequence);
  const deadline = Date.now() + 5 * 60 * 1000;

  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 5000));

    try {
      const resp = await client.get('/v1/wrapped-key');

      if (resp.status === 200) {
        const data = await resp.arrayBuffer();
        return new Uint8Array(data);
      }
      // 404 = not yet available, keep polling
    } catch {
      // Network error, keep polling
    }

    process.stderr.write('.');
  }

  return null;
}

function findSSHPublicKey(): string | null {
  const sshDir = path.join(os.homedir(), '.ssh');
  const candidates = ['id_ed25519.pub', 'id_rsa.pub'];

  for (const candidate of candidates) {
    const keyPath = path.join(sshDir, candidate);
    if (fs.existsSync(keyPath)) {
      return keyPath;
    }
  }

  return null;
}
