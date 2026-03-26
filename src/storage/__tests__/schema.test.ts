import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import BetterSqlite3 from 'better-sqlite3';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { initializeSchema, migrateSchema, SCHEMA_VERSION } from '../schema.js';

describe('schema', () => {
  let tmpDir: string;
  let dbPath: string;
  let db: BetterSqlite3.Database;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chaoskb-schema-test-'));
    dbPath = path.join(tmpDir, 'test.db');
    db = new BetterSqlite3(dbPath);
  });

  afterEach(() => {
    db.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('SCHEMA_VERSION', () => {
    it('should be 2', () => {
      expect(SCHEMA_VERSION).toBe(2);
    });
  });

  describe('initializeSchema', () => {
    it('should create all tables', () => {
      initializeSchema(db);

      const tables = db
        .prepare(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
        .all() as { name: string }[];

      const tableNames = tables.map((t) => t.name);
      expect(tableNames).toContain('sources');
      expect(tableNames).toContain('chunks');
      expect(tableNames).toContain('sync_status');
      expect(tableNames).toContain('schema_version');
    });

    it('should set the schema version', () => {
      initializeSchema(db);

      const row = db.prepare('SELECT version FROM schema_version').get() as { version: number };
      expect(row.version).toBe(SCHEMA_VERSION);
    });

    it('should be idempotent', () => {
      initializeSchema(db);
      initializeSchema(db);

      const rows = db.prepare('SELECT version FROM schema_version').all() as { version: number }[];
      expect(rows).toHaveLength(1);
      expect(rows[0].version).toBe(SCHEMA_VERSION);
    });

    it('should create sources table with correct columns', () => {
      initializeSchema(db);

      const info = db.prepare('PRAGMA table_info(sources)').all() as {
        name: string;
        type: string;
        notnull: number;
      }[];

      const columns = info.map((c) => c.name);
      expect(columns).toEqual([
        'id',
        'url',
        'title',
        'tags',
        'chunk_count',
        'blob_size_bytes',
        'created_at',
        'updated_at',
        'last_accessed_at',
        'deleted_at',
      ]);
    });

    it('should create chunks table with correct columns', () => {
      initializeSchema(db);

      const info = db.prepare('PRAGMA table_info(chunks)').all() as { name: string }[];
      const columns = info.map((c) => c.name);
      expect(columns).toEqual([
        'id',
        'source_id',
        'chunk_index',
        'content',
        'embedding',
        'token_count',
        'model',
      ]);
    });

    it('should create sync_status table with correct columns', () => {
      initializeSchema(db);

      const info = db.prepare('PRAGMA table_info(sync_status)').all() as { name: string }[];
      const columns = info.map((c) => c.name);
      expect(columns).toEqual(['blob_id', 'status', 'last_attempt', 'error_message']);
    });

    it('should enforce unique constraint on chunks(source_id, chunk_index)', () => {
      initializeSchema(db);

      db.prepare('INSERT INTO sources (id, url) VALUES (?, ?)').run('src1', 'http://example.com');
      db.prepare(
        'INSERT INTO chunks (id, source_id, chunk_index, content) VALUES (?, ?, ?, ?)',
      ).run('c1', 'src1', 0, 'hello');

      expect(() => {
        db.prepare(
          'INSERT INTO chunks (id, source_id, chunk_index, content) VALUES (?, ?, ?, ?)',
        ).run('c2', 'src1', 0, 'world');
      }).toThrow();
    });
  });

  describe('migrateSchema', () => {
    it('should handle already up-to-date schema', () => {
      initializeSchema(db);
      migrateSchema(db);

      const row = db.prepare('SELECT version FROM schema_version').get() as { version: number };
      expect(row.version).toBe(SCHEMA_VERSION);
    });

    it('should handle missing version row', () => {
      // Create the schema_version table but with no rows
      db.exec('CREATE TABLE schema_version (version INTEGER NOT NULL)');
      // Also create the other tables
      db.exec(`CREATE TABLE IF NOT EXISTS sources (
        id TEXT PRIMARY KEY,
        url TEXT NOT NULL,
        title TEXT NOT NULL DEFAULT '',
        tags TEXT NOT NULL DEFAULT '[]',
        chunk_count INTEGER NOT NULL DEFAULT 0,
        blob_size_bytes INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        last_accessed_at TEXT NOT NULL DEFAULT (datetime('now')),
        deleted_at TEXT
      )`);

      migrateSchema(db);

      const row = db.prepare('SELECT version FROM schema_version').get() as { version: number };
      expect(row.version).toBe(SCHEMA_VERSION);
    });
  });
});
