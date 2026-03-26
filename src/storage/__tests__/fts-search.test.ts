import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { KBDatabase } from '../kb-database.js';

describe('FTS5 Keyword Search', () => {
  let tmpDir: string;
  let db: KBDatabase;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chaoskb-fts-test-'));
    db = new KBDatabase({ path: path.join(tmpDir, 'test.db') });

    // Insert test sources and chunks
    db.sources.insert({
      id: 'src-js',
      url: 'https://example.com/js',
      title: 'JavaScript Guide',
      tags: ['javascript'],
      chunkCount: 2,
      blobSizeBytes: 500,
    });

    db.sources.insert({
      id: 'src-py',
      url: 'https://example.com/py',
      title: 'Python Guide',
      tags: ['python'],
      chunkCount: 2,
      blobSizeBytes: 500,
    });

    db.chunks.insertMany([
      {
        sourceId: 'src-js',
        chunkIndex: 0,
        content: 'JavaScript closures allow functions to access variables from their outer scope even after the outer function has returned.',
        embedding: new Float32Array(3),
        tokenCount: 20,
        model: 'test',
      },
      {
        sourceId: 'src-js',
        chunkIndex: 1,
        content: 'Promises in JavaScript provide a way to handle asynchronous operations with then, catch, and finally methods.',
        embedding: new Float32Array(3),
        tokenCount: 18,
        model: 'test',
      },
      {
        sourceId: 'src-py',
        chunkIndex: 0,
        content: 'Python generators use the yield keyword to produce values lazily without storing them all in memory.',
        embedding: new Float32Array(3),
        tokenCount: 17,
        model: 'test',
      },
      {
        sourceId: 'src-py',
        chunkIndex: 1,
        content: 'List comprehensions in Python provide a concise way to create lists from existing iterables with optional filtering.',
        embedding: new Float32Array(3),
        tokenCount: 18,
        model: 'test',
      },
    ]);
  });

  afterEach(() => {
    db.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should find chunks matching a keyword', () => {
    const results = db.chunks.searchKeyword('closures', 10);
    expect(results.length).toBe(1);
    expect(results[0].sourceId).toBe('src-js');
    expect(results[0].chunkIndex).toBe(0);
    expect(results[0].content).toContain('closures');
  });

  it('should find chunks matching multiple keywords', () => {
    const results = db.chunks.searchKeyword('JavaScript asynchronous', 10);
    expect(results.length).toBeGreaterThanOrEqual(1);
    // The promises chunk should be ranked highest (matches both words)
    const promisesResult = results.find((r) => r.chunkIndex === 1 && r.sourceId === 'src-js');
    expect(promisesResult).toBeDefined();
  });

  it('should rank results by relevance', () => {
    const results = db.chunks.searchKeyword('Python', 10);
    expect(results.length).toBeGreaterThanOrEqual(2);
    // All results should have Python-related content
    for (const r of results) {
      expect(r.sourceId).toBe('src-py');
    }
  });

  it('should return snippets with match context', () => {
    const results = db.chunks.searchKeyword('generators', 10);
    expect(results.length).toBe(1);
    expect(results[0].snippet.length).toBeGreaterThan(0);
  });

  it('should support phrase search', () => {
    const results = db.chunks.searchKeyword('"yield keyword"', 10);
    expect(results.length).toBe(1);
    expect(results[0].sourceId).toBe('src-py');
    expect(results[0].chunkIndex).toBe(0);
  });

  it('should return empty for no matches', () => {
    const results = db.chunks.searchKeyword('quantum computing', 10);
    expect(results.length).toBe(0);
  });

  it('should return empty for empty query', () => {
    const results = db.chunks.searchKeyword('', 10);
    expect(results.length).toBe(0);
  });

  it('should respect topK limit', () => {
    const results = db.chunks.searchKeyword('JavaScript OR Python', 1);
    expect(results.length).toBe(1);
  });

  it('should handle invalid FTS5 syntax gracefully', () => {
    // Malformed query should not throw
    const results = db.chunks.searchKeyword('AND OR NOT', 10);
    expect(Array.isArray(results)).toBe(true);
  });

  it('should reflect new inserts in search', () => {
    db.sources.insert({
      id: 'src-rust',
      url: 'https://example.com/rust',
      title: 'Rust Guide',
      tags: ['rust'],
      chunkCount: 1,
      blobSizeBytes: 200,
    });

    db.chunks.insertMany([{
      sourceId: 'src-rust',
      chunkIndex: 0,
      content: 'Rust ownership model prevents memory leaks and data races at compile time.',
      embedding: new Float32Array(3),
      tokenCount: 12,
      model: 'test',
    }]);

    const results = db.chunks.searchKeyword('ownership', 10);
    expect(results.length).toBe(1);
    expect(results[0].sourceId).toBe('src-rust');
  });

  it('should reflect deletions in search', () => {
    // Verify it exists first
    let results = db.chunks.searchKeyword('closures', 10);
    expect(results.length).toBe(1);

    // Delete the JavaScript chunks
    db.chunks.deleteBySourceId('src-js');

    // Should no longer appear in search
    results = db.chunks.searchKeyword('closures', 10);
    expect(results.length).toBe(0);
  });

  it('should support prefix search', () => {
    const results = db.chunks.searchKeyword('async*', 10);
    expect(results.length).toBe(1);
    expect(results[0].content).toContain('asynchronous');
  });
});
