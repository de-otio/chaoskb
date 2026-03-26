import type BetterSqlite3 from 'better-sqlite3';

export const SCHEMA_VERSION = 2;

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
