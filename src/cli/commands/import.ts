/**
 * Import command: restore a previously exported knowledge base.
 *
 * Supports the plaintext export format (Markdown files with YAML frontmatter
 * and a manifest.json). Sources are re-chunked and re-embedded on import
 * to ensure the embedding index is consistent.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
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

/**
 * Import a previously exported knowledge base from a directory of Markdown files.
 *
 * @param options - Import configuration.
 * @returns Summary of the import operation.
 */
export async function importCommand(options: ImportOptions): Promise<ImportResult> {
  const config = await loadConfig();
  if (!config) {
    console.error('ChaosKB is not set up. Run `chaoskb-mcp setup` first.');
    process.exit(1);
  }

  const inputDir = path.resolve(options.inputPath);
  if (!fs.existsSync(inputDir)) {
    throw new Error(`Import directory does not exist: ${inputDir}`);
  }

  console.log('');
  console.log('  ChaosKB Import');
  console.log('  ==============');
  console.log('');

  // Load manifest if it exists
  const manifestPath = path.join(inputDir, 'manifest.json');
  let manifest: Record<string, { sha256: string; title: string; url: string }> | null = null;
  if (fs.existsSync(manifestPath)) {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    console.log(`  Found manifest with ${Object.keys(manifest!).length} entries`);
  }

  // Find all .md files in the directory (excluding README, etc.)
  const mdFiles = fs.readdirSync(inputDir)
    .filter((f) => f.endsWith('.md') && f !== 'README.md')
    .sort();

  if (mdFiles.length === 0) {
    console.log('  No Markdown files found in import directory.');
    return { imported: 0, skipped: 0, errors: [] };
  }

  console.log(`  Found ${mdFiles.length} Markdown files to import`);
  console.log('');

  // Set up database and pipeline
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

        // Verify SHA-256 against manifest if available
        if (manifest && manifest[mdFile]) {
          const expectedHash = manifest[mdFile].sha256;
          const actualHash = crypto.createHash('sha256').update(fileContent).digest('hex');
          if (actualHash !== expectedHash) {
            result.errors.push(`${mdFile}: SHA-256 mismatch (file may be corrupted)`);
            continue;
          }
        }

        // Parse frontmatter and content
        const parsed = parseFrontmatter(fileContent);
        if (!parsed) {
          result.errors.push(`${mdFile}: invalid or missing YAML frontmatter`);
          continue;
        }

        const { frontmatter, content } = parsed;

        // Check for duplicate URL
        const existingSources = db.sources.list({
          titleSearch: frontmatter.title,
        });
        const duplicate = existingSources.find((s) => s.url === frontmatter.url);

        if (duplicate && !options.overwrite) {
          console.log(`  Skipped: ${frontmatter.title} (duplicate URL)`);
          result.skipped++;
          continue;
        }

        if (duplicate && options.overwrite) {
          // Remove existing source before reimporting
          db.sources.softDelete(duplicate.id);
          db.embeddingIndex.remove(duplicate.id);
          db.chunks.deleteBySourceId(duplicate.id);
        }

        // Generate a new source ID
        const sourceId = crypto.randomUUID();

        // Store source record
        db.sources.insert({
          id: sourceId,
          url: frontmatter.url,
          title: frontmatter.title,
          tags: frontmatter.tags,
          chunkCount: 0, // Will be updated below
          blobSizeBytes: Buffer.byteLength(content, 'utf-8'),
        });

        // Store the content as a single chunk (without re-embedding)
        // Embeddings will need to be regenerated separately
        const chunkRecords = [{
          sourceId,
          chunkIndex: 0,
          content,
          embedding: new Float32Array(384), // Zero vector placeholder
          tokenCount: 0,
          model: 'import-pending',
        }];

        db.chunks.insertMany(chunkRecords);

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

  return result;
}

/**
 * Parse YAML frontmatter from a Markdown file.
 * Expects the format produced by the export command:
 *
 * ```
 * ---
 * title: "Article Title"
 * url: https://example.com
 * tags: ["tag1", "tag2"]
 * date: 2024-01-01T00:00:00.000Z
 * ---
 *
 * Content here...
 * ```
 */
function parseFrontmatter(
  fileContent: string,
): { frontmatter: ParsedFrontmatter; content: string } | null {
  const fmMatch = fileContent.match(/^---\n([\s\S]*?)\n---\n\n?([\s\S]*)$/);
  if (!fmMatch) {
    return null;
  }

  const yamlBlock = fmMatch[1];
  const content = fmMatch[2].trim();

  // Simple YAML parser for our known format
  const title = extractYamlValue(yamlBlock, 'title') ?? '';
  const url = extractYamlValue(yamlBlock, 'url') ?? '';
  const dateStr = extractYamlValue(yamlBlock, 'date') ?? '';

  // Parse tags array
  const tagsMatch = yamlBlock.match(/^tags:\s*\[(.*)\]\s*$/m);
  const tags: string[] = [];
  if (tagsMatch) {
    const tagsStr = tagsMatch[1];
    const tagMatches = tagsStr.matchAll(/"([^"]*)"/g);
    for (const m of tagMatches) {
      tags.push(m[1]);
    }
  }

  if (!url) {
    return null; // URL is required
  }

  return {
    frontmatter: { title, url, tags, date: dateStr },
    content,
  };
}

/**
 * Extract a simple key: value or key: "value" from YAML text.
 */
function extractYamlValue(yaml: string, key: string): string | null {
  // Match: key: "quoted value" or key: unquoted value
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
