import type BetterSqlite3 from 'better-sqlite3';
import { existsSync, readFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

export const SCHEMA_VERSION = 4;

export const CREATE_TABLES_SQL: string[] = [
  `CREATE TABLE IF NOT EXISTS sources (
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
  )`,
  `CREATE TABLE IF NOT EXISTS chunks (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES sources(id),
    chunk_index INTEGER NOT NULL,
    content TEXT NOT NULL,
    embedding BLOB,
    token_count INTEGER NOT NULL DEFAULT 0,
    model TEXT NOT NULL DEFAULT '',
    UNIQUE(source_id, chunk_index)
  )`,
  `CREATE TABLE IF NOT EXISTS sync_status (
    blob_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'local_only',
    last_attempt TEXT,
    error_message TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
  )`,
  // FTS5 virtual table for keyword search over chunk content
  `CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    content,
    source_id UNINDEXED,
    chunk_index UNINDEXED,
    content='chunks',
    content_rowid='rowid'
  )`,
  // Triggers to keep FTS index in sync with the chunks table
  `CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
    INSERT INTO chunks_fts(rowid, content, source_id, chunk_index)
    VALUES (new.rowid, new.content, new.source_id, new.chunk_index);
  END`,
  `CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
    INSERT INTO chunks_fts(chunks_fts, rowid, content, source_id, chunk_index)
    VALUES ('delete', old.rowid, old.content, old.source_id, old.chunk_index);
  END`,
  `CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON chunks BEGIN
    INSERT INTO chunks_fts(chunks_fts, rowid, content, source_id, chunk_index)
    VALUES ('delete', old.rowid, old.content, old.source_id, old.chunk_index);
    INSERT INTO chunks_fts(rowid, content, source_id, chunk_index)
    VALUES (new.rowid, new.content, new.source_id, new.chunk_index);
  END`,
  // --- v3: Sync infrastructure tables ---
  `CREATE TABLE IF NOT EXISTS sync_sequence (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    value INTEGER NOT NULL DEFAULT 0
  )`,
  `INSERT OR IGNORE INTO sync_sequence (id, value) VALUES (1, 0)`,
  `CREATE TABLE IF NOT EXISTS sync_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blob_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('upload', 'delete')),
    data BLOB,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 5,
    last_attempt TEXT,
    next_attempt TEXT,
    error_message TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'processing', 'failed', 'completed')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`,
  `CREATE INDEX IF NOT EXISTS idx_sync_queue_status
    ON sync_queue(status, next_attempt)`,
  `CREATE INDEX IF NOT EXISTS idx_sync_queue_blob
    ON sync_queue(blob_id)`,
  `CREATE TABLE IF NOT EXISTS sync_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`,
];

export function initializeSchema(db: BetterSqlite3.Database): void {
  const existing = db
    .prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'`)
    .get() as { name: string } | undefined;

  if (existing) {
    // Schema already exists, run migrations instead
    migrateSchema(db);
    return;
  }

  db.transaction(() => {
    for (const sql of CREATE_TABLES_SQL) {
      db.exec(sql);
    }
    db.prepare('INSERT INTO schema_version (version) VALUES (?)').run(SCHEMA_VERSION);
  })();
}

export function migrateSchema(db: BetterSqlite3.Database): void {
  const row = db.prepare('SELECT version FROM schema_version').get() as
    | { version: number }
    | undefined;

  if (!row) {
    // No version row — initialize from scratch
    for (const sql of CREATE_TABLES_SQL) {
      db.exec(sql);
    }
    db.prepare('INSERT INTO schema_version (version) VALUES (?)').run(SCHEMA_VERSION);
    return;
  }

  const currentVersion = row.version;

  if (currentVersion >= SCHEMA_VERSION) {
    return; // Already up to date
  }

  if (currentVersion < 2) {
    runMigrationV2(db);
  }

  if (currentVersion < 3) {
    runMigrationV3(db);
  }

  if (currentVersion < 4) {
    runMigrationV4(db);
  }

  db.prepare('UPDATE schema_version SET version = ?').run(SCHEMA_VERSION);
}

/**
 * Migration v2: Add FTS5 full-text search index for keyword search.
 */
function runMigrationV2(db: BetterSqlite3.Database): void {
  db.exec(`CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
    content,
    source_id UNINDEXED,
    chunk_index UNINDEXED,
    content='chunks',
    content_rowid='rowid'
  )`);

  db.exec(`CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
    INSERT INTO chunks_fts(rowid, content, source_id, chunk_index)
    VALUES (new.rowid, new.content, new.source_id, new.chunk_index);
  END`);

  db.exec(`CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
    INSERT INTO chunks_fts(chunks_fts, rowid, content, source_id, chunk_index)
    VALUES ('delete', old.rowid, old.content, old.source_id, old.chunk_index);
  END`);

  db.exec(`CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON chunks BEGIN
    INSERT INTO chunks_fts(chunks_fts, rowid, content, source_id, chunk_index)
    VALUES ('delete', old.rowid, old.content, old.source_id, old.chunk_index);
    INSERT INTO chunks_fts(rowid, content, source_id, chunk_index)
    VALUES (new.rowid, new.content, new.source_id, new.chunk_index);
  END`);

  // Backfill: populate FTS index from existing chunk data
  db.exec(`INSERT INTO chunks_fts(rowid, content, source_id, chunk_index)
    SELECT rowid, content, source_id, chunk_index FROM chunks`);
}

/**
 * Migration v3: Add sync infrastructure tables.
 *
 * Moves sequence counter, upload queue, and sync state from flat files
 * into SQLite for safe multi-process concurrent access.
 */
function runMigrationV3(db: BetterSqlite3.Database): void {
  db.exec(`CREATE TABLE IF NOT EXISTS sync_sequence (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    value INTEGER NOT NULL DEFAULT 0
  )`);
  db.exec(`INSERT OR IGNORE INTO sync_sequence (id, value) VALUES (1, 0)`);

  db.exec(`CREATE TABLE IF NOT EXISTS sync_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blob_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('upload', 'delete')),
    data BLOB,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 5,
    last_attempt TEXT,
    next_attempt TEXT,
    error_message TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'processing', 'failed', 'completed')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_sync_queue_status
    ON sync_queue(status, next_attempt)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_sync_queue_blob
    ON sync_queue(blob_id)`);

  db.exec(`CREATE TABLE IF NOT EXISTS sync_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`);

  // Import existing flat-file data if present
  importFlatFileData(db);
}

/**
 * Import data from legacy flat files into SQLite tables.
 * Reads ~/.chaoskb/sequence, upload-queue.json, and sync-state.json.
 * Files are left on disk as rollback backups.
 */
function importFlatFileData(db: BetterSqlite3.Database): void {
  const chaoskbDir = join(homedir(), '.chaoskb');

  // Import sequence counter
  const seqPath = join(chaoskbDir, 'sequence');
  if (existsSync(seqPath)) {
    try {
      const value = parseInt(readFileSync(seqPath, 'utf-8').trim(), 10);
      if (!isNaN(value) && value > 0) {
        db.prepare('UPDATE sync_sequence SET value = ? WHERE id = 1').run(value);
      }
      try { renameSync(seqPath, seqPath + '.migrated'); } catch { /* already renamed */ }
    } catch { /* ignore read errors */ }
  }

  // Import upload queue
  const queuePath = join(chaoskbDir, 'upload-queue.json');
  if (existsSync(queuePath)) {
    try {
      const items = JSON.parse(readFileSync(queuePath, 'utf-8')) as Array<{
        blobId: string;
        data: string;
        retryCount: number;
        error?: string;
      }>;
      const insertStmt = db.prepare(`
        INSERT OR IGNORE INTO sync_queue (blob_id, operation, data, retry_count, error_message, status)
        VALUES (?, 'upload', ?, ?, ?, 'pending')
      `);
      for (const item of items) {
        const data = item.data ? Buffer.from(item.data, 'base64') : null;
        insertStmt.run(item.blobId, data, item.retryCount, item.error ?? null);
      }
      try { renameSync(queuePath, queuePath + '.migrated'); } catch { /* already renamed */ }
    } catch { /* ignore parse errors */ }
  }

  // Import sync state
  const statePath = join(chaoskbDir, 'sync-state.json');
  if (existsSync(statePath)) {
    try {
      const state = JSON.parse(readFileSync(statePath, 'utf-8')) as Record<string, unknown>;
      const insertStmt = db.prepare('INSERT OR IGNORE INTO sync_state (key, value) VALUES (?, ?)');
      for (const [key, value] of Object.entries(state)) {
        if (value !== undefined && value !== null) {
          insertStmt.run(key, String(value));
        }
      }
      try { renameSync(statePath, statePath + '.migrated'); } catch { /* already renamed */ }
    } catch { /* ignore parse errors */ }
  }
}

/**
 * Migration v4: Reset stale sync queue items.
 *
 * After fixing WAF body size blocking and sequence counter drift,
 * previously failed/retried items need a fresh attempt.
 */
function runMigrationV4(db: BetterSqlite3.Database): void {
  db.exec(`
    UPDATE sync_queue
    SET status = 'pending',
        retry_count = 0,
        error_message = NULL,
        next_attempt = NULL
    WHERE status IN ('pending', 'failed')
      AND retry_count > 0
  `);
}
