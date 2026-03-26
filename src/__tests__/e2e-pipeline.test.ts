/**
 * End-to-end integration test for the ChaosKB pipeline.
 *
 * Tests the full round-trip: HTTP fetch → extract → chunk → embed → store → search → delete.
 *
 * Uses a real SQLite database, real HTML extraction, real WordPiece chunking,
 * and a mock embedder (to avoid downloading the 134MB ONNX model in tests).
 * The mock embedder produces deterministic embeddings based on text content
 * so that search results are predictable.
 */

import { createServer, type Server } from 'node:http';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { KBDatabase } from '../storage/kb-database.js';
import { ContentPipeline } from '../pipeline/content-pipeline.js';
import { handleKbIngest } from '../cli/tools/kb-ingest.js';
import { handleKbQuery } from '../cli/tools/kb-query.js';
import { handleKbDelete } from '../cli/tools/kb-delete.js';
import { SyncStatus } from '../storage/types.js';
import type { EmbeddingVector } from '../pipeline/types.js';
import type { McpDependencies } from '../cli/mcp-server.js';

// --- Fixture HTML pages ---

const ARTICLE_JS = `<!DOCTYPE html>
<html>
<head><title>JavaScript Closures Explained</title></head>
<body>
  <article>
    <h1>JavaScript Closures Explained</h1>
    <p>A closure is a function that retains access to its lexical scope even when the function is executed outside that scope. Closures are fundamental to JavaScript and enable powerful patterns like data privacy and function factories.</p>
    <p>When a function is declared inside another function, the inner function has access to the outer function's variables. This access persists even after the outer function has returned. The inner function "closes over" the variables it references.</p>
    <p>Common use cases for closures include event handlers, callbacks, and module patterns. In modern JavaScript, closures power many frameworks and libraries, making them essential knowledge for developers.</p>
  </article>
</body>
</html>`;

const ARTICLE_PYTHON = `<!DOCTYPE html>
<html>
<head><title>Python Generators and Iterators</title></head>
<body>
  <article>
    <h1>Python Generators and Iterators</h1>
    <p>Generators in Python are a special type of iterator that allow you to iterate over data without storing it all in memory. They use the yield keyword instead of return, producing values one at a time and suspending their state between each yield.</p>
    <p>This makes generators ideal for processing large datasets, reading files line by line, or implementing infinite sequences. The memory efficiency of generators is their primary advantage over regular lists or tuples.</p>
    <p>Python iterators implement the iterator protocol with __iter__ and __next__ methods. Generators automatically implement this protocol, making them the easiest way to create custom iterators in Python.</p>
  </article>
</body>
</html>`;

// --- Mock Embedder ---

/**
 * A deterministic mock embedder that produces distinct embeddings based on text content.
 * Uses simple word hashing to create 384-dim vectors that cluster similar texts together.
 */
function createDeterministicEmbedder() {
  const dim = 384;

  function textToEmbedding(text: string): EmbeddingVector {
    const vec = new Float32Array(dim);
    const words = text.toLowerCase().split(/\s+/);

    for (const word of words) {
      // Hash each word to a dimension and add weight
      let hash = 0;
      for (let i = 0; i < word.length; i++) {
        hash = (hash * 31 + word.charCodeAt(i)) & 0x7fffffff;
      }
      const idx = hash % dim;
      vec[idx] += 1.0;
    }

    // L2 normalize
    let mag = 0;
    for (let i = 0; i < dim; i++) mag += vec[i] * vec[i];
    mag = Math.sqrt(mag);
    if (mag > 0) {
      for (let i = 0; i < dim; i++) vec[i] /= mag;
    }

    return vec;
  }

  return {
    embed: vi.fn(async (text: string) => textToEmbedding(text)),
    embedBatch: vi.fn(async (texts: string[]) => texts.map(textToEmbedding)),
    initialize: vi.fn(async () => {}),
    dispose: vi.fn(),
    modelPath: '/mock/model.onnx',
    vocabPath: '/mock/vocab.txt',
  };
}

// --- Mock Encryption ---

function createMockEncryption() {
  let blobCounter = 0;
  return {
    generateMasterKey: vi.fn(() => ({ expose: () => new Uint8Array(32), destroy: vi.fn() })),
    deriveKeys: vi.fn(() => ({
      contentKey: { expose: () => new Uint8Array(32), destroy: vi.fn() },
      metadataKey: { expose: () => new Uint8Array(32), destroy: vi.fn() },
      embeddingKey: { expose: () => new Uint8Array(32), destroy: vi.fn() },
      commitKey: { expose: () => new Uint8Array(32), destroy: vi.fn() },
    })),
    encrypt: vi.fn(() => ({ ciphertext: new Uint8Array(16), envelope: {} })),
    decrypt: vi.fn(() => ({ payload: {} })),
    generateBlobId: vi.fn(() => `blob-${++blobCounter}`),
  };
}

// --- Test HTTP server ---

let server: Server;
let serverUrl: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.url === '/js-closures') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(ARTICLE_JS);
    } else if (req.url === '/python-generators') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(ARTICLE_PYTHON);
    } else {
      res.writeHead(404);
      res.end('Not found');
    }
  });

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const addr = server.address() as { port: number };
  serverUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

// --- Tests ---

describe('End-to-end pipeline', () => {
  let tmpDir: string;
  let db: KBDatabase;
  let deps: McpDependencies;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chaoskb-e2e-'));
    db = new KBDatabase({ path: path.join(tmpDir, 'test.db') });

    const embedder = createDeterministicEmbedder();
    const pipeline = new ContentPipeline({}, embedder as never);
    const encryption = createMockEncryption();
    const keys = encryption.deriveKeys(encryption.generateMasterKey());

    deps = {
      db,
      dbManager: {} as never,
      pipeline,
      encryption: encryption as never,
      keys: keys as never,
    };
  });

  afterEach(() => {
    db.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('ingests a URL, stores all data, and makes it searchable', async () => {
    // Ingest the JavaScript article
    const result = await handleKbIngest(
      { url: `${serverUrl}/js-closures`, tags: ['javascript', 'closures'] },
      deps,
    );

    // Verify ingest result
    expect(result.title).toBe('JavaScript Closures Explained');
    expect(result.url).toBe(`${serverUrl}/js-closures`);
    expect(result.chunkCount).toBeGreaterThanOrEqual(1);
    expect(result.blobIds.length).toBe(result.chunkCount + 1); // source + chunks

    // Verify source stored
    const source = db.sources.getById(result.blobIds[0]);
    expect(source).not.toBeNull();
    expect(source!.title).toBe('JavaScript Closures Explained');
    expect(source!.tags).toEqual(['javascript', 'closures']);

    // Verify chunks stored
    const chunks = db.chunks.getBySourceId(result.blobIds[0]);
    expect(chunks.length).toBe(result.chunkCount);
    for (const chunk of chunks) {
      expect(chunk.content.length).toBeGreaterThan(0);
      expect(chunk.embedding).toBeInstanceOf(Float32Array);
      expect(chunk.embedding.length).toBe(384);
    }

    // Verify sync status set
    for (const blobId of result.blobIds) {
      const status = db.syncStatus.get(blobId);
      expect(status).not.toBeNull();
      expect(status!.status).toBe('local_only');
    }

    // Verify embedding index loaded
    expect(db.embeddingIndex.size).toBe(result.chunkCount);
  });

  it('searches and returns relevant results', async () => {
    // Ingest two articles
    await handleKbIngest(
      { url: `${serverUrl}/js-closures`, tags: ['javascript'] },
      deps,
    );
    await handleKbIngest(
      { url: `${serverUrl}/python-generators`, tags: ['python'] },
      deps,
    );

    // Search for JavaScript-related content
    const searchResult = await handleKbQuery(
      { query: 'closures functions scope JavaScript', limit: 5 },
      deps,
    );

    expect(searchResult.results.length).toBeGreaterThanOrEqual(1);

    // The top result should be from the JavaScript article
    const topResult = searchResult.results[0];
    expect(topResult.title).toBe('JavaScript Closures Explained');
    expect(topResult.score).toBeGreaterThan(0);
    expect(topResult.content.length).toBeGreaterThan(0);

    // Search for Python-related content
    const pySearch = await handleKbQuery(
      { query: 'generators iterators yield Python memory', limit: 5 },
      deps,
    );

    expect(pySearch.results.length).toBeGreaterThanOrEqual(1);
    expect(pySearch.results[0].title).toBe('Python Generators and Iterators');
  });

  it('soft-deletes a source and removes it from search', async () => {
    // Ingest an article
    const result = await handleKbIngest(
      { url: `${serverUrl}/js-closures` },
      deps,
    );
    const sourceId = result.blobIds[0];

    // Verify it's searchable
    const beforeDelete = await handleKbQuery({ query: 'closures scope', limit: 1 }, deps);
    expect(beforeDelete.results.length).toBeGreaterThanOrEqual(1);

    // Delete it
    const deleteResult = await handleKbDelete({ id: sourceId }, deps);
    expect(deleteResult.deleted).toBe(true);

    // Verify it's gone from search
    const afterDelete = await handleKbQuery({ query: 'closures scope', limit: 1 }, deps);
    expect(afterDelete.results.length).toBe(0);

    // Verify source is soft-deleted in DB
    const source = db.sources.getById(sourceId);
    expect(source).not.toBeNull();
    expect(source!.deletedAt).toBeDefined();

    // Verify sync status updated
    const status = db.syncStatus.get(sourceId);
    expect(status!.status).toBe(SyncStatus.PendingDelete);
  });

  it('handles multiple ingest + delete cycles without corruption', async () => {
    // Ingest first
    const r1 = await handleKbIngest({ url: `${serverUrl}/js-closures` }, deps);
    expect(db.embeddingIndex.size).toBe(r1.chunkCount);

    // Ingest second
    const r2 = await handleKbIngest({ url: `${serverUrl}/python-generators` }, deps);
    expect(db.embeddingIndex.size).toBe(r1.chunkCount + r2.chunkCount);

    // Delete first
    await handleKbDelete({ id: r1.blobIds[0] }, deps);
    expect(db.embeddingIndex.size).toBe(r2.chunkCount);

    // Search should only return Python results
    const search = await handleKbQuery({ query: 'closures generators Python', limit: 10 }, deps);
    for (const item of search.results) {
      expect(item.title).toBe('Python Generators and Iterators');
    }

    // Delete second
    await handleKbDelete({ id: r2.blobIds[0] }, deps);
    expect(db.embeddingIndex.size).toBe(0);

    // Search should return nothing
    const emptySearch = await handleKbQuery({ query: 'anything', limit: 10 }, deps);
    expect(emptySearch.results.length).toBe(0);
  });

  it('correctly extracts content from real HTML', async () => {
    const result = await handleKbIngest(
      { url: `${serverUrl}/js-closures` },
      deps,
    );

    const chunks = db.chunks.getBySourceId(result.blobIds[0]);
    // All chunk content should contain real text, not HTML
    for (const chunk of chunks) {
      expect(chunk.content).not.toContain('<h1>');
      expect(chunk.content).not.toContain('<p>');
      expect(chunk.content).not.toContain('<article>');
    }
    // Content should mention closures
    const allContent = chunks.map((c) => c.content).join(' ');
    expect(allContent.toLowerCase()).toContain('closure');
  });

  it('rejects delete of nonexistent source', async () => {
    await expect(
      handleKbDelete({ id: 'nonexistent-id' }, deps),
    ).rejects.toThrow('Source not found');
  });

  it('rejects double delete', async () => {
    const result = await handleKbIngest(
      { url: `${serverUrl}/js-closures` },
      deps,
    );
    const sourceId = result.blobIds[0];

    await handleKbDelete({ id: sourceId }, deps);
    await expect(
      handleKbDelete({ id: sourceId }, deps),
    ).rejects.toThrow('already deleted');
  });
});
