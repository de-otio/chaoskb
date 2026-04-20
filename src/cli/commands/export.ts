import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import * as crypto from 'node:crypto';
import { loadConfig } from './setup.js';
import type { CanaryPayload } from '../../crypto/types.js';

export interface ExportOptions {
  format: 'encrypted' | 'plaintext';
  outputPath: string;
  projectName?: string;
}

function prompt(rl: readline.Interface, question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
}

export async function exportCommand(options: ExportOptions): Promise<void> {
  const config = await loadConfig();
  if (!config) {
    console.error('ChaosKB is not set up. Run `chaoskb-mcp setup` first.');
    process.exit(1);
  }

  const outputDir = path.resolve(options.outputPath);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  console.log('');
  console.log('  ChaosKB Export');
  console.log('  ==============');
  console.log('');

  if (options.format === 'encrypted') {
    await exportEncrypted(outputDir);
  } else {
    await exportPlaintext(outputDir);
  }
}

async function exportEncrypted(outputDir: string): Promise<void> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    console.log('  Format: encrypted (envelope format with Argon2id-wrapped key)');
    console.log('');

    // Prompt for export passphrase
    const passphrase = await prompt(rl, '  Enter export passphrase: ');
    if (!passphrase || passphrase.length < 8) {
      console.log('  Passphrase must be at least 8 characters. Export cancelled.');
      return;
    }

    const confirm = await prompt(rl, '  Confirm passphrase: ');
    if (passphrase !== confirm) {
      console.log('  Passphrases do not match. Export cancelled.');
      return;
    }

    console.log('');
    console.log('  Deriving wrapping key with Argon2id...');

    const { DatabaseManager } = await import('../../storage/database-manager.js');
    const { EncryptionService } = await import('../../crypto/encryption-service.js');
    const { deriveFromPassphrase: argon2Derive } = await import(
      '@de-otio/crypto-envelope/primitives'
    );

    // Note: we don't need the personal master for encrypted export — the
    // wrapping key is derived directly from the user-supplied export
    // passphrase. Previously we retrieved the master for no reason other
    // than to dispose it; the keyring unlock path has non-trivial cost
    // so skip it here.

    // Derive wrapping key from export passphrase
    const salt = crypto.randomBytes(32);
    const derived = argon2Derive(passphrase, salt);

    // Encrypt canary with wrapping key (verifies passphrase on import)
    const encryption = new EncryptionService();
    const wrappingKeys = encryption.deriveKeys(derived);
    const canary: CanaryPayload = { type: 'canary', value: 'chaoskb-canary-v1' };
    const wrappedCanary = encryption.encrypt(canary, wrappingKeys);

    // Collect all sources and chunks from DB
    const dbManager = new DatabaseManager();
    const db = dbManager.getPersonalDb();
    const sources = db.sources.list({}, { limit: 100000, offset: 0 });

    const exportSources: Array<{
      id: string;
      url: string;
      title: string;
      tags: string[];
      chunks: Array<{ index: number; content: string; tokenCount: number }>;
    }> = [];

    for (const source of sources) {
      const chunks = db.chunks.getBySourceId(source.id);
      exportSources.push({
        id: source.id,
        url: source.url,
        title: source.title,
        tags: source.tags,
        chunks: chunks
          .sort((a, b) => a.chunkIndex - b.chunkIndex)
          .map((c) => ({ index: c.chunkIndex, content: c.content, tokenCount: c.tokenCount })),
      });
    }

    // Encrypt the source data using AEAD directly (not via envelope — data is not a Payload type)
    const { aeadEncrypt } = await import('../../crypto/aead.js');
    const sourcesJson = JSON.stringify(exportSources);
    const sourcesBytes = new TextEncoder().encode(sourcesJson);
    const dataKey = new Uint8Array(wrappingKeys.contentKey.buffer);
    const aad = new TextEncoder().encode('chaoskb-export-data');
    const { nonce, ciphertext, tag } = aeadEncrypt(dataKey, sourcesBytes, aad);

    // Concatenate nonce + ciphertext + tag
    const encryptedData = new Uint8Array(nonce.length + ciphertext.length + tag.length);
    encryptedData.set(nonce, 0);
    encryptedData.set(ciphertext, nonce.length);
    encryptedData.set(tag, nonce.length + ciphertext.length);

    const exportData = {
      version: 1,
      format: 'chaoskb-export-encrypted',
      exportedAt: new Date().toISOString(),
      wrappedKey: {
        alg: 'argon2id',
        salt: salt.toString('base64'),
        params: { m: 262144, t: 3, p: 1 },
        ct: Buffer.from(wrappedCanary.bytes).toString('base64'),
      },
      data: Buffer.from(encryptedData).toString('base64'),
      sourceCount: sources.length,
    };

    dbManager.closeAll();

    const outputFile = path.join(outputDir, 'chaoskb-export.json');
    fs.writeFileSync(outputFile, JSON.stringify(exportData, null, 2), {
      mode: 0o600,
    });

    console.log(`  Exported to: ${outputFile}`);
    console.log('');
  } finally {
    rl.close();
  }
}

async function exportPlaintext(outputDir: string): Promise<void> {
  console.log('  Format: plaintext (Markdown files)');
  console.log('');

  // In production:
  // 1. Open database and list all sources
  // 2. For each source, get all chunks
  // 3. Write each source as a Markdown file with YAML frontmatter
  // 4. Generate manifest.json with SHA-256 hashes

  const manifest: Record<string, { sha256: string; title: string; url: string }> = {};

  const { DatabaseManager } = await import('../../storage/database-manager.js');
  const dbManager = new DatabaseManager();
  const db = dbManager.getPersonalDb();

  const sources = db.sources.list({}, { limit: 100000, offset: 0 });

  for (const source of sources) {
    const chunks = db.chunks.getBySourceId(source.id);
    const content = chunks
      .sort((a, b) => a.chunkIndex - b.chunkIndex)
      .map((c) => c.content)
      .join('\n\n');
    const frontmatter = [
      '---',
      `title: "${(source.title ?? '').replace(/"/g, '\\"')}"`,
      `url: ${source.url}`,
      `tags: [${(source.tags ?? []).map((t) => `"${t}"`).join(', ')}]`,
      `date: ${source.createdAt}`,
      '---',
    ].join('\n');
    const fileContent = `${frontmatter}\n\n${content}\n`;
    const safeName = sanitizeFilename(source.title ?? source.id);
    const filePath = path.join(outputDir, `${safeName}.md`);
    fs.writeFileSync(filePath, fileContent);
    const hash = crypto.createHash('sha256').update(fileContent).digest('hex');
    manifest[`${safeName}.md`] = { sha256: hash, title: source.title ?? '', url: source.url };
  }

  dbManager.closeAll();

  const manifestPath = path.join(outputDir, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

  console.log(`  Exported to: ${outputDir}`);
  console.log(`  Manifest: ${manifestPath}`);
  console.log(`  Files: ${Object.keys(manifest).length}`);
  console.log('');
}

/**
 * Sanitize a string for use as a filename.
 * Removes characters not safe for filesystems and truncates to reasonable length.
 */
export function sanitizeFilename(name: string): string {
  return name
    .replace(/[/\\?%*:|"<>]/g, '-')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, 200)
    || 'untitled';
}
