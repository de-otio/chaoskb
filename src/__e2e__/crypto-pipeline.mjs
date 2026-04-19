/**
 * E2E test: Crypto pipeline (T5)
 *
 * Exercises the full crypto stack: key generation -> derivation ->
 * encryption -> decryption, using the app's own modules.
 *
 * Exit 0 = pass, exit 1 = fail.
 */

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

console.log('\n=== Crypto Pipeline ===');

try {
  const { EncryptionService } = await import('../dist/crypto/encryption-service.js');
  // `SecureBuffer` now lives in @de-otio/crypto-envelope — the chaoskb
  // re-export module (crypto/secure-buffer.js) was removed in the
  // keyring migration.
  const { SecureBuffer } = await import('@de-otio/crypto-envelope');

  const encryption = new EncryptionService();

  // 1. Generate master key
  const masterKey = encryption.generateMasterKey();
  assert(masterKey.length === 32, 'master key is 32 bytes');
  assert(!masterKey.isDisposed, 'master key is not disposed');

  // 2. Derive key set
  const keys = encryption.deriveKeys(masterKey);
  assert(keys.contentKey.length === 32, 'content key is 32 bytes');
  assert(keys.metadataKey.length === 32, 'metadata key is 32 bytes');
  assert(keys.embeddingKey.length === 32, 'embedding key is 32 bytes');
  assert(keys.commitKey.length === 32, 'commit key is 32 bytes');

  // Verify keys are distinct
  assert(
    !keys.contentKey.buffer.equals(keys.metadataKey.buffer),
    'content key != metadata key',
  );

  // 3. Encrypt a canary payload
  const payload = { type: 'canary', value: 'chaoskb-canary-v1' };
  const { envelope } = encryption.encrypt(payload, keys, 'CEK');
  assert(envelope.v === 1, 'envelope version is 1');
  assert(envelope.enc.alg === 'XChaCha20-Poly1305', 'algorithm is XChaCha20-Poly1305');
  assert(envelope.enc.kid === 'CEK', 'key id is CEK');
  assert(typeof envelope.enc.ct === 'string' && envelope.enc.ct.length > 0, 'ciphertext is non-empty');
  assert(typeof envelope.enc.commit === 'string' && envelope.enc.commit.length > 0, 'commitment is non-empty');

  // 4. Decrypt and verify round-trip
  const { payload: decrypted } = encryption.decrypt(envelope, keys);
  assert(decrypted.type === 'canary', 'decrypted type matches');
  assert(decrypted.value === 'chaoskb-canary-v1', 'decrypted value matches');

  // 5. Encrypt a chunk payload (closer to real usage)
  const chunkPayload = {
    type: 'chunk',
    sourceId: 'b_test123',
    index: 0,
    model: 'snowflake-arctic-embed-s',
    content: 'The quick brown fox jumps over the lazy dog.',
    tokenCount: 10,
    embedding: Array.from({ length: 384 }, (_, i) => Math.sin(i)),
  };
  const { envelope: chunkEnv } = encryption.encrypt(chunkPayload, keys, 'CEK');
  const { payload: chunkDecrypted } = encryption.decrypt(chunkEnv, keys);
  assert(chunkDecrypted.type === 'chunk', 'chunk type round-trips');
  assert(chunkDecrypted.content === chunkPayload.content, 'chunk content round-trips');
  assert(chunkDecrypted.embedding.length === 384, 'chunk embedding length round-trips');
  assert(
    Math.abs(chunkDecrypted.embedding[0] - Math.sin(0)) < 1e-6,
    'chunk embedding values round-trip',
  );

  // 6. Verify wrong keys fail decryption
  const otherMasterKey = encryption.generateMasterKey();
  const otherKeys = encryption.deriveKeys(otherMasterKey);
  let decryptFailed = false;
  try {
    encryption.decrypt(envelope, otherKeys);
  } catch {
    decryptFailed = true;
  }
  assert(decryptFailed, 'decryption with wrong keys throws');

  // Cleanup
  masterKey.dispose();
  otherMasterKey.dispose();
  keys.contentKey.dispose();
  keys.metadataKey.dispose();
  keys.embeddingKey.dispose();
  keys.commitKey.dispose();
  otherKeys.contentKey.dispose();
  otherKeys.metadataKey.dispose();
  otherKeys.embeddingKey.dispose();
  otherKeys.commitKey.dispose();
} catch (err) {
  console.error(`  FAIL: Unexpected error: ${err.message}`);
  console.error(err.stack);
  failed++;
}

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
