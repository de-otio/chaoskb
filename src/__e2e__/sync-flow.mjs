/**
 * E2E test: Sync flow (T8)
 *
 * Exercises the full sync pipeline against the live server for both
 * Ed25519 and RSA key types:
 *   register -> upload blob -> verify blob exists -> delete blob -> verify deleted
 *
 * Requires CHAOSKB_SYNC_ENDPOINT env var (defaults to https://sync.chaoskb.com).
 * Uses fresh ephemeral key pairs for isolation.
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
 * Generate a temporary SSH key pair in OpenSSH format.
 * Supports 'ed25519' and 'rsa' key types.
 */
async function generateTempSSHKey(dir, keyType = 'ed25519') {
  const sshpk = (await import('sshpk')).default;

  if (keyType === 'ed25519') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const rawPub = spkiDer.subarray(spkiDer.length - 32);

    const typeStr = Buffer.from('ssh-ed25519');
    const typeLenBuf = Buffer.alloc(4);
    typeLenBuf.writeUInt32BE(typeStr.length);
    const pubLenBuf = Buffer.alloc(4);
    pubLenBuf.writeUInt32BE(rawPub.length);
    const sshPubBlob = Buffer.concat([typeLenBuf, typeStr, pubLenBuf, rawPub]);
    const sshPubLine = `ssh-ed25519 ${sshPubBlob.toString('base64')} e2e-test`;

    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const parsedKey = sshpk.parsePrivateKey(privPem, 'pkcs8');
    const opensshPriv = parsedKey.toString('ssh');

    const keyPath = join(dir, 'id_ed25519');
    writeFileSync(keyPath, opensshPriv, { mode: 0o600 });
    writeFileSync(keyPath + '.pub', sshPubLine, { mode: 0o644 });
    return { keyPath };
  }

  if (keyType === 'rsa') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });

    // Convert to OpenSSH format via sshpk
    const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const parsedKey = sshpk.parsePrivateKey(privPem, 'pkcs8');
    const opensshPriv = parsedKey.toString('ssh');

    // Generate the SSH public key line
    const parsedPub = parsedKey.toPublic();
    const sshPubLine = parsedPub.toString('ssh') + ' e2e-test';

    const keyPath = join(dir, 'id_rsa');
    writeFileSync(keyPath, opensshPriv, { mode: 0o600 });
    writeFileSync(keyPath + '.pub', sshPubLine, { mode: 0o644 });
    return { keyPath };
  }

  throw new Error(`Unsupported key type: ${keyType}`);
}

/**
 * Register the key with the sync server using challenge-response.
 */
async function registerKey(keyPath) {
  const { SSHSigner } = await import('../dist/sync/ssh-signer.js');
  const signer = new SSHSigner(keyPath);

  const challengeRes = await fetch(`${ENDPOINT}/v1/register/challenge`);
  assert(challengeRes.ok, `challenge endpoint returned ${challengeRes.status}`);
  const { challenge } = await challengeRes.json();

  const { signature, publicKey } = await signer.signRegistrationChallenge(challenge);

  const regRes = await fetch(`${ENDPOINT}/v1/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey, signedChallenge: signature, challengeNonce: challenge }),
  });
  assert(regRes.status === 201 || regRes.status === 409, `registration returned ${regRes.status}`);
  await regRes.json(); // consume body

  return signer;
}

/**
 * Run the full sync flow for one key type.
 */
async function runSyncFlow(keyType) {
  console.log(`\n  --- ${keyType.toUpperCase()} ---`);
  const tempDir = mkdtempSync(join(tmpdir(), `chaoskb-e2e-sync-${keyType}-`));

  try {
    // 1. Generate ephemeral key pair
    const { keyPath } = await generateTempSSHKey(tempDir, keyType);
    console.log(`  Generated ephemeral ${keyType} key pair`);

    // 2. Register with server
    const signer = await registerKey(keyPath);
    console.log('  Registered with sync server');

    // 3. Create authenticated client with a temporary sequence counter
    const { SyncHttpClient } = await import('../dist/sync/http-client.js');
    const { SequenceCounter } = await import('../dist/sync/sequence.js');
    const seqPath = join(tempDir, 'sequence');
    const httpClient = new SyncHttpClient(
      { endpoint: ENDPOINT, sshKeyPath: keyPath },
      signer,
      new SequenceCounter(seqPath),
    );

    // 4. Encrypt a test blob
    const { EncryptionService } = await import('../dist/crypto/encryption-service.js');
    const encryption = new EncryptionService();
    const masterKey = encryption.generateMasterKey();
    const keys = encryption.deriveKeys(masterKey);
    const { bytes: encryptedBytes } = encryption.encrypt(
      { type: 'canary', value: 'chaoskb-canary-v1' },
      keys,
      'CEK',
    );
    assert(encryptedBytes.length > 0, `[${keyType}] encrypted blob has content`);

    const blobId = encryption.generateBlobId();
    console.log(`  Encrypted test blob: ${blobId} (${encryptedBytes.length} bytes)`);

    // 5. Upload
    const putRes = await httpClient.put(`/v1/blobs/${blobId}`, encryptedBytes);
    assert(putRes.ok, `[${keyType}] PUT blob returned ${putRes.status}`);
    const putBody = await putRes.json();
    assert(putBody.id === blobId, `[${keyType}] PUT response contains correct blobId`);
    console.log('  Uploaded blob to server');

    // 6. GET blob
    const getRes = await httpClient.get(`/v1/blobs/${blobId}`);
    assert(getRes.ok, `[${keyType}] GET blob returned ${getRes.status}`);
    const blobData = await getRes.arrayBuffer();
    assert(blobData.byteLength > 0, `[${keyType}] GET blob returned non-empty data`);
    console.log('  Verified blob exists on server');

    // 7. Blob count
    const countRes = await httpClient.get('/v1/blobs/count');
    assert(countRes.ok, `[${keyType}] GET blob count returned ${countRes.status}`);
    const countBody = await countRes.json();
    assert(countBody.count >= 1, `[${keyType}] blob count is ${countBody.count} (>= 1)`);

    // 8. List
    const listRes = await httpClient.get('/v1/blobs');
    assert(listRes.ok, `[${keyType}] GET blob list returned ${listRes.status}`);
    const listBody = await listRes.json();
    assert(listBody.blobs.some(b => b.id === blobId), `[${keyType}] blob in list`);

    // 9. Delete
    const delRes = await httpClient.delete(`/v1/blobs/${blobId}`);
    assert(delRes.ok, `[${keyType}] DELETE blob returned ${delRes.status}`);

    // 10. Verify tombstone
    const getAfterDel = await httpClient.get(`/v1/blobs/${blobId}`);
    assert(getAfterDel.status === 404, `[${keyType}] GET deleted blob returned 404`);

    const listAfterDel = await httpClient.get('/v1/blobs');
    assert(listAfterDel.ok, `[${keyType}] list after delete is ok`);
    const listAfterBody = await listAfterDel.json();
    assert(listAfterBody.tombstones?.some(t => t.id === blobId), `[${keyType}] tombstone in list`);

    console.log(`  ${keyType.toUpperCase()} flow complete`);
    masterKey.dispose();
  } finally {
    try { rmSync(tempDir, { recursive: true }); } catch { /* ignore */ }
  }
}

console.log(`\n=== Sync Flow (${ENDPOINT}) ===`);

try {
  // Run both key types sequentially (avoid rate limiting)
  await runSyncFlow('ed25519');
  await new Promise(r => setTimeout(r, 2000)); // pause between registrations
  await runSyncFlow('rsa');
} catch (err) {
  console.error(`  ERROR: ${err.message}`);
  console.error(err.stack);
  failed++;
}

console.log(`\n  Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
