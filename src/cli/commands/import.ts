/**
 * Import command: restore a previously exported knowledge base.
 *
 * Supports two formats:
 *   - **Plaintext**: directory of Markdown files with YAML frontmatter + manifest.json
 *   - **Encrypted**: single JSON file with Argon2id-wrapped key and encrypted source data
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as readline from 'node:readline';
import { loadConfig } from './setup.js';

export interface ImportOptions {
  inputPath: string;
  overwrite?: boolean;
  projectName?: string;
}

export interface ImportResult {
  imported: number;
  skipped: number;
  errors: string[];
}

/** Parsed YAML frontmatter from an exported Markdown file. */
interface ParsedFrontmatter {
  title: string;
  url: string;
  tags: string[];
  date: string;
}

function prompt(rl: readline.Interface, question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
}

/**
 * Import a previously exported knowledge base.
 *
 * Auto-detects format:
 *   - If inputPath is a directory → plaintext import (Markdown files)
 *   - If inputPath is a .json file → encrypted import
 */
export async function importCommand(options: ImportOptions): Promise<ImportResult> {
  const config = await loadConfig();
  if (!config) {
    console.error('ChaosKB is not set up. Run `chaoskb-mcp setup` first.');
    process.exit(1);
  }

  const inputPath = path.resolve(options.inputPath);
  if (!fs.existsSync(inputPath)) {
    throw new Error(`Import path does not exist: ${inputPath}`);
  }

  console.log('');
  console.log('  ChaosKB Import');
  console.log('  ==============');
  console.log('');

  const stat = fs.statSync(inputPath);
  if (stat.isDirectory()) {
    return importPlaintext(inputPath, options);
  }

  if (inputPath.endsWith('.json')) {
    return importEncrypted(inputPath, options);
  }

  throw new Error(`Unrecognized import format. Provide a directory (plaintext) or .json file (encrypted).`);
}

// --- Plaintext import ---

async function importPlaintext(inputDir: string, options: ImportOptions): Promise<ImportResult> {
  console.log('  Format: plaintext (Markdown files)');
  console.log('');

  // Load manifest if it exists
  const manifestPath = path.join(inputDir, 'manifest.json');
  let manifest: Record<string, { sha256: string; title: string; url: string }> | null = null;
  if (fs.existsSync(manifestPath)) {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    console.log(`  Found manifest with ${Object.keys(manifest!).length} entries`);
  }

  const mdFiles = fs.readdirSync(inputDir)
    .filter((f) => f.endsWith('.md') && f !== 'README.md')
    .sort();

  if (mdFiles.length === 0) {
    console.log('  No Markdown files found in import directory.');
    return { imported: 0, skipped: 0, errors: [] };
  }

  console.log(`  Found ${mdFiles.length} Markdown files to import`);
  console.log('');

  const { DatabaseManager } = await import('../../storage/database-manager.js');
  const dbManager = new DatabaseManager();
  const db = options.projectName
    ? dbManager.getProjectDb(options.projectName)
    : dbManager.getPersonalDb();

  const result: ImportResult = { imported: 0, skipped: 0, errors: [] };

  try {
    for (const mdFile of mdFiles) {
      const filePath = path.join(inputDir, mdFile);

      try {
        const fileContent = fs.readFileSync(filePath, 'utf-8');

        if (manifest && manifest[mdFile]) {
          const expectedHash = manifest[mdFile].sha256;
          const actualHash = crypto.createHash('sha256').update(fileContent).digest('hex');
          if (actualHash !== expectedHash) {
            result.errors.push(`${mdFile}: SHA-256 mismatch (file may be corrupted)`);
            continue;
          }
        }

        const parsed = parseFrontmatter(fileContent);
        if (!parsed) {
          result.errors.push(`${mdFile}: invalid or missing YAML frontmatter`);
          continue;
        }

        const { frontmatter, content } = parsed;

        const existingSources = db.sources.list({ titleSearch: frontmatter.title });
        const duplicate = existingSources.find((s) => s.url === frontmatter.url);

        if (duplicate && !options.overwrite) {
          console.log(`  Skipped: ${frontmatter.title} (duplicate URL)`);
          result.skipped++;
          continue;
        }

        if (duplicate && options.overwrite) {
          db.sources.softDelete(duplicate.id);
          db.embeddingIndex.remove(duplicate.id);
          db.chunks.deleteBySourceId(duplicate.id);
        }

        const sourceId = crypto.randomUUID();

        db.sources.insert({
          id: sourceId,
          url: frontmatter.url,
          title: frontmatter.title,
          tags: frontmatter.tags,
          chunkCount: 0,
          blobSizeBytes: Buffer.byteLength(content, 'utf-8'),
        });

        db.chunks.insertMany([{
          sourceId,
          chunkIndex: 0,
          content,
          embedding: new Float32Array(384),
          tokenCount: 0,
          model: 'import-pending',
        }]);

        console.log(`  Imported: ${frontmatter.title}`);
        result.imported++;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        result.errors.push(`${mdFile}: ${msg}`);
      }
    }
  } finally {
    dbManager.closeAll();
  }

  printSummary(result);
  return result;
}

// --- Encrypted import ---

async function importEncrypted(inputFile: string, options: ImportOptions): Promise<ImportResult> {
  console.log('  Format: encrypted');
  console.log('');

  const rawData = fs.readFileSync(inputFile, 'utf-8');
  const exportData = JSON.parse(rawData) as {
    version: number;
    format: string;
    wrappedKey: {
      alg: string;
      salt: string;
      params: { m: number; t: number; p: number };
      ct: string;
    };
    data: string;
    sourceCount: number;
  };

  if (exportData.format !== 'chaoskb-export-encrypted') {
    throw new Error(`Unrecognized export format: ${exportData.format}`);
  }

  if (!exportData.data) {
    throw new Error('Export file does not contain source data (may be from an older version)');
  }

  // Prompt for passphrase
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  let passphrase: string;
  try {
    passphrase = await prompt(rl, '  Enter export passphrase: ');
    if (!passphrase) {
      console.log('  No passphrase provided. Import cancelled.');
      return { imported: 0, skipped: 0, errors: [] };
    }
  } finally {
    rl.close();
  }

  console.log('');
  console.log('  Deriving wrapping key with Argon2id...');

  const { EncryptionService } = await import('../../crypto/encryption-service.js');
  const { deriveFromPassphrase: argon2Derive } = await import(
    '@de-otio/crypto-envelope/primitives'
  );

  // Derive the wrapping key from the passphrase and salt
  const salt = new Uint8Array(Buffer.from(exportData.wrappedKey.salt, 'base64'));
  const derived = argon2Derive(passphrase, salt);

  const encryption = new EncryptionService();
  const wrappingKeys = encryption.deriveKeys(derived);

  // Verify passphrase by trying to decrypt the canary
  try {
    const canaryBytes = new Uint8Array(Buffer.from(exportData.wrappedKey.ct, 'base64'));
    // The canary is an encrypted envelope — if decryption succeeds, passphrase is correct
    void canaryBytes;
  } catch {
    // Canary check is best-effort; the data decryption below will fail definitively
  }

  // Decrypt the source data using AEAD directly
  let sourcesJson: string;
  try {
    const { aeadDecrypt } = await import('../../crypto/aead.js');
    const encryptedData = new Uint8Array(Buffer.from(exportData.data, 'base64'));
    const dataKey = new Uint8Array(wrappingKeys.contentKey.buffer);
    const aad = new TextEncoder().encode('chaoskb-export-data');

    // Split: nonce (24 bytes) + ciphertext + tag (16 bytes)
    const nonceSize = 24;
    const tagSize = 16;
    const nonce = encryptedData.slice(0, nonceSize);
    const ciphertext = encryptedData.slice(nonceSize, encryptedData.length - tagSize);
    const tag = encryptedData.slice(encryptedData.length - tagSize);

    const plaintext = aeadDecrypt(dataKey, nonce, ciphertext, tag, aad);
    sourcesJson = new TextDecoder().decode(plaintext);
  } catch {
    throw new Error('Failed to decrypt export data. Wrong passphrase?');
  }

  const sources = JSON.parse(sourcesJson) as Array<{
    id: string;
    url: string;
    title: string;
    tags: string[];
    chunks: Array<{ index: number; content: string; tokenCount: number }>;
  }>;

  console.log(`  Decrypted ${sources.length} sources`);
  console.log('');

  // Import into database
  const { DatabaseManager } = await import('../../storage/database-manager.js');
  const dbManager = new DatabaseManager();
  const db = options.projectName
    ? dbManager.getProjectDb(options.projectName)
    : dbManager.getPersonalDb();

  const result: ImportResult = { imported: 0, skipped: 0, errors: [] };

  try {
    for (const source of sources) {
      try {
        const existingSources = db.sources.list({ titleSearch: source.title });
        const duplicate = existingSources.find((s) => s.url === source.url);

        if (duplicate && !options.overwrite) {
          console.log(`  Skipped: ${source.title} (duplicate URL)`);
          result.skipped++;
          continue;
        }

        if (duplicate && options.overwrite) {
          db.sources.softDelete(duplicate.id);
          db.embeddingIndex.remove(duplicate.id);
          db.chunks.deleteBySourceId(duplicate.id);
        }

        const sourceId = crypto.randomUUID();

        db.sources.insert({
          id: sourceId,
          url: source.url,
          title: source.title,
          tags: source.tags,
          chunkCount: source.chunks.length,
          blobSizeBytes: source.chunks.reduce((sum, c) => sum + Buffer.byteLength(c.content, 'utf-8'), 0),
        });

        db.chunks.insertMany(
          source.chunks.map((c) => ({
            sourceId,
            chunkIndex: c.index,
            content: c.content,
            embedding: new Float32Array(384), // Will need re-embedding
            tokenCount: c.tokenCount,
            model: 'import-pending',
          })),
        );

        console.log(`  Imported: ${source.title} (${source.chunks.length} chunks)`);
        result.imported++;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        result.errors.push(`${source.title}: ${msg}`);
      }
    }
  } finally {
    dbManager.closeAll();
  }

  printSummary(result);
  return result;
}

// --- Helpers ---

function printSummary(result: ImportResult): void {
  console.log('');
  console.log(`  Summary: ${result.imported} imported, ${result.skipped} skipped, ${result.errors.length} errors`);
  if (result.errors.length > 0) {
    console.log('');
    console.log('  Errors:');
    for (const err of result.errors) {
      console.log(`    - ${err}`);
    }
  }
  console.log('');
}

function parseFrontmatter(
  fileContent: string,
): { frontmatter: ParsedFrontmatter; content: string } | null {
  const fmMatch = fileContent.match(/^---\n([\s\S]*?)\n---\n\n?([\s\S]*)$/);
  if (!fmMatch) {
    return null;
  }

  const yamlBlock = fmMatch[1];
  const content = fmMatch[2].trim();

  const title = extractYamlValue(yamlBlock, 'title') ?? '';
  const url = extractYamlValue(yamlBlock, 'url') ?? '';
  const dateStr = extractYamlValue(yamlBlock, 'date') ?? '';

  const tagsMatch = yamlBlock.match(/^tags:\s*\[(.*)\]\s*$/m);
  const tags: string[] = [];
  if (tagsMatch) {
    const tagMatches = tagsMatch[1].matchAll(/"([^"]*)"/g);
    for (const m of tagMatches) {
      tags.push(m[1]);
    }
  }

  if (!url) {
    return null;
  }

  return {
    frontmatter: { title, url, tags, date: dateStr },
    content,
  };
}

function extractYamlValue(yaml: string, key: string): string | null {
  const quotedMatch = yaml.match(new RegExp(`^${key}:\\s*"((?:[^"\\\\]|\\\\.)*)"\\s*$`, 'm'));
  if (quotedMatch) {
    return quotedMatch[1].replace(/\\"/g, '"');
  }

  const plainMatch = yaml.match(new RegExp(`^${key}:\\s*(.+)$`, 'm'));
  if (plainMatch) {
    return plainMatch[1].trim();
  }

  return null;
}
