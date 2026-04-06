/**
 * E2E test: Sync flow (T8)
 *
 * Exercises the full sync pipeline against the live server:
 *   register -> upload blob -> verify blob exists -> delete blob -> verify deleted
 *
 * Requires CHAOSKB_SYNC_ENDPOINT env var (defaults to https://sync.chaoskb.com).
 * Uses a fresh ephemeral Ed25519 key pair for isolation.
 *
 * Exit 0 = pass, exit 1 = fail.
 */

import * as crypto from 'node:crypto';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const ENDPOINT = process.env.CHAOSKB_SYNC_ENDPOINT || 'https://sync.chaoskb.com';

let passed = 0;
let failed = 0;
let tempDir;

function assert(condition, message) {
  if (!condition) {
    console.error(`  FAIL: ${message}`);
    failed++;
  } else {
    console.log(`  PASS: ${message}`);
    passed++;
  }
}

/**
 * Generate a temporary Ed25519 SSH key pair in OpenSSH format.
 * Returns the path to the private key file.
 */
async function generateTempSSHKey(dir) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

  // Export public key in SSH wire format
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const rawPub = spkiDer.subarray(spkiDer.length - 32);

  // Build SSH public key blob: string "ssh-ed25519" + bytes rawPub
  const typeStr = Buffer.from('ssh-ed25519');
  const typeLenBuf = Buffer.alloc(4);
  typeLenBuf.writeUInt32BE(typeStr.length);
  const pubLenBuf = Buffer.alloc(4);
  pubLenBuf.writeUInt32BE(rawPub.length);
  const sshPubBlob = Buffer.concat([typeLenBuf, typeStr, pubLenBuf, rawPub]);
  const sshPubLine = `ssh-ed25519 ${sshPubBlob.toString('base64')} e2e-test`;

  // Write private key in OpenSSH format using ssh-keygen compatible PEM
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

  // We need to write in OpenSSH format for SSHSigner.
  // Use sshpk to convert PKCS8 -> OpenSSH format.
  const sshpk = (await import('sshpk')).default;
  const parsedKey = sshpk.parsePrivateKey(privPem, 'pkcs8');
  const opensshPriv = parsedKey.toString('ssh');

  const keyPath = join(dir, 'id_ed25519');
  const pubPath = join(dir, 'id_ed25519.pub');
  writeFileSync(keyPath, opensshPriv, { mode: 0o600 });
  writeFileSync(pubPath, sshPubLine, { mode: 0o644 });

  return { keyPath, pubPath, sshPubBlob };
}

/**
 * Register the key with the sync server using challenge-response.
 */
async function registerKey(keyPath, sshPubBlob) {
  const { SSHSigner } = await import('../dist/sync/ssh-signer.js');
  const signer = new SSHSigner(keyPath);

  // Step 1: Get challenge
  const challengeRes = await fetch(`${ENDPOINT}/v1/register/challenge`);
  assert(challengeRes.ok, `challenge endpoint returned ${challengeRes.status}`);
  const { challenge } = await challengeRes.json();
  assert(typeof challenge === 'string' && challenge.length > 0, 'challenge is non-empty string');

  // Step 2: Sign challenge
  const { signature, publicKey } = await signer.signRegistrationChallenge(challenge);
  assert(typeof signature === 'string' && signature.length > 0, 'signature is non-empty');
  assert(typeof publicKey === 'string' && publicKey.length > 0, 'publicKey is non-empty');

  // Step 3: Register
  const regRes = await fetch(`${ENDPOINT}/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      publicKey,
      signedChallenge: signature,
      challengeNonce: challenge,
    }),
  });
  assert(regRes.status === 201 || regRes.status === 409, `registration returned ${regRes.status}`);
  const regBody = await regRes.json();
  assert(regBody.tenantId || regBody.error === 'already_registered', `registration body: ${JSON.stringify(regBody)}`);

  return signer;
}

console.log(`\n=== Sync Flow (${ENDPOINT}) ===`);

try {
  tempDir = mkdtempSync(join(tmpdir(), 'chaoskb-e2e-sync-'));

  // 1. Generate ephemeral key pair
  const { keyPath, sshPubBlob } = await generateTempSSHKey(tempDir);
  console.log('  Generated ephemeral Ed25519 key pair');

  // 2. Register with server
  const signer = await registerKey(keyPath, sshPubBlob);
  console.log('  Registered with sync server');

  // 3. Create SyncHttpClient for authenticated requests
  const { SyncHttpClient } = await import('../dist/sync/http-client.js');
  const httpClient = new SyncHttpClient({ endpoint: ENDPOINT, sshKeyPath: keyPath }, signer);

  // 4. Encrypt a test blob
  const { EncryptionService } = await import('../dist/crypto/encryption-service.js');
  const encryption = new EncryptionService();
  const masterKey = encryption.generateMasterKey();
  const keys = encryption.deriveKeys(masterKey);

  const testPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
  const { bytes: encryptedBytes } = encryption.encrypt(testPayload, keys, 'CEK');
  assert(encryptedBytes.length > 0, 'encrypted blob has content');

  const blobId = encryption.generateBlobId();
  console.log(`  Encrypted test blob: ${blobId} (${encryptedBytes.length} bytes)`);

  // 5. Upload the blob
  const putRes = await httpClient.put(`/v1/blobs/${blobId}`, encryptedBytes);
  assert(putRes.ok, `PUT blob returned ${putRes.status}`);
  const putBody = await putRes.json();
  assert(putBody.id === blobId, 'PUT response contains correct blobId');
  console.log('  Uploaded blob to server');

  // 6. Verify blob exists — GET blob
  const getRes = await httpClient.get(`/v1/blobs/${blobId}`);
  assert(getRes.ok, `GET blob returned ${getRes.status}`);
  // Blob content should be retrievable
  const blobData = await getRes.arrayBuffer();
  assert(blobData.byteLength > 0, 'GET blob returned non-empty data');
  console.log('  Verified blob exists on server');

  // 7. Verify blob count
  const countRes = await httpClient.get('/v1/blobs/count');
  assert(countRes.ok, `GET blob count returned ${countRes.status}`);
  const countBody = await countRes.json();
  assert(countBody.count >= 1, `blob count is ${countBody.count} (>= 1)`);
  console.log(`  Blob count: ${countBody.count}`);

  // 8. Verify blob appears in list
  const listRes = await httpClient.get('/v1/blobs');
  assert(listRes.ok, `GET blob list returned ${listRes.status}`);
  const listBody = await listRes.json();
  const found = listBody.blobs.some(b => b.id === blobId);
  assert(found, 'uploaded blob appears in blob list');
  console.log('  Blob appears in list');

  // 9. Delete the blob
  const delRes = await httpClient.delete(`/v1/blobs/${blobId}`);
  assert(delRes.ok, `DELETE blob returned ${delRes.status}`);
  console.log('  Deleted blob from server');

  // 10. Verify blob is gone (should be tombstoned)
  const getAfterDel = await httpClient.get(`/v1/blobs/${blobId}`);
  assert(getAfterDel.status === 404, `GET deleted blob returned ${getAfterDel.status} (expected 404)`);
  console.log('  Verified blob is tombstoned');

  // 11. Verify tombstone appears in list
  const listAfterDel = await httpClient.get('/v1/blobs');
  assert(listAfterDel.ok, 'list after delete is ok');
  const listAfterBody = await listAfterDel.json();
  const tombstone = listAfterBody.tombstones?.some(t => t.id === blobId);
  assert(tombstone, 'deleted blob appears as tombstone in list');
  console.log('  Tombstone appears in list');

  // Clean up master key
  masterKey.dispose();

} catch (err) {
  console.error(`  ERROR: ${err.message}`);
  console.error(err.stack);
  failed++;
} finally {
  if (tempDir) {
    try { rmSync(tempDir, { recursive: true }); } catch { /* ignore */ }
  }
}

console.log(`\n  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
