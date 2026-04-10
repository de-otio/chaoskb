import type BetterSqlite3 from 'better-sqlite3';
import type {
  ISourceRepository,
  SourceRecord,
  SourceFilter,
  PaginationOptions,
} from './types.js';

interface SourceRow {
  id: string;
  url: string;
  title: string;
  tags: string;
  chunk_count: number;
  blob_size_bytes: number;
  created_at: string;
  updated_at: string;
  last_accessed_at: string;
  deleted_at: string | null;
}

function rowToRecord(row: SourceRow): SourceRecord {
  return {
    id: row.id,
    url: row.url,
    title: row.title,
    tags: JSON.parse(row.tags) as string[],
    chunkCount: row.chunk_count,
    blobSizeBytes: row.blob_size_bytes,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastAccessedAt: row.last_accessed_at,
    deletedAt: row.deleted_at ?? undefined,
  };
}

export class SourceRepository implements ISourceRepository {
  private readonly db: BetterSqlite3.Database;

  private readonly insertStmt: BetterSqlite3.Statement;
  private readonly getByIdStmt: BetterSqlite3.Statement;
  private readonly getByUrlStmt: BetterSqlite3.Statement;
  private readonly softDeleteStmt: BetterSqlite3.Statement;
  private readonly restoreStmt: BetterSqlite3.Statement;
  private readonly updateLastAccessedStmt: BetterSqlite3.Statement;

  constructor(db: BetterSqlite3.Database) {
    this.db = db;

    this.insertStmt = db.prepare(`
      INSERT INTO sources (id, url, title, tags, chunk_count, blob_size_bytes)
      VALUES (@id, @url, @title, @tags, @chunkCount, @blobSizeBytes)
    `);

    this.getByIdStmt = db.prepare('SELECT * FROM sources WHERE id = ?');

    this.getByUrlStmt = db.prepare(
      'SELECT * FROM sources WHERE url = ? AND deleted_at IS NULL LIMIT 1',
    );

    this.softDeleteStmt = db.prepare(
      `UPDATE sources SET deleted_at = datetime('now'), updated_at = datetime('now') WHERE id = ? AND deleted_at IS NULL`,
    );

    this.restoreStmt = db.prepare(
      `UPDATE sources SET deleted_at = NULL, updated_at = datetime('now') WHERE id = ? AND deleted_at IS NOT NULL`,
    );

    this.updateLastAccessedStmt = db.prepare(
      `UPDATE sources SET last_accessed_at = datetime('now') WHERE id = ?`,
    );
  }

  insert(
    source: Omit<SourceRecord, 'createdAt' | 'updatedAt' | 'lastAccessedAt'>,
  ): SourceRecord {
    this.insertStmt.run({
      id: source.id,
      url: source.url,
      title: source.title,
      tags: JSON.stringify(source.tags),
      chunkCount: source.chunkCount,
      blobSizeBytes: source.blobSizeBytes,
    });

    return this.getById(source.id)!;
  }

  getById(id: string): SourceRecord | null {
    const row = this.getByIdStmt.get(id) as SourceRow | undefined;
    return row ? rowToRecord(row) : null;
  }

  getByUrl(url: string): SourceRecord | null {
    const row = this.getByUrlStmt.get(url) as SourceRow | undefined;
    return row ? rowToRecord(row) : null;
  }

  list(filter?: SourceFilter, pagination?: PaginationOptions): SourceRecord[] {
    const { sql, params } = this.buildFilterQuery('SELECT *', filter, pagination);
    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as SourceRow[];
    return rows.map(rowToRecord);
  }

  count(filter?: SourceFilter): number {
    const { sql, params } = this.buildFilterQuery('SELECT COUNT(*) as cnt', filter);
    const stmt = this.db.prepare(sql);
    const row = stmt.get(...params) as { cnt: number };
    return row.cnt;
  }

  softDelete(id: string): boolean {
    const result = this.softDeleteStmt.run(id);
    return result.changes > 0;
  }

  restore(id: string): boolean {
    const result = this.restoreStmt.run(id);
    return result.changes > 0;
  }

  updateLastAccessed(id: string): void {
    this.updateLastAccessedStmt.run(id);
  }

  private buildFilterQuery(
    selectClause: string,
    filter?: SourceFilter,
    pagination?: PaginationOptions,
  ): { sql: string; params: unknown[] } {
    const conditions: string[] = [];
    const params: unknown[] = [];

    // Default: exclude deleted unless includeDeleted is true
    if (!filter?.includeDeleted) {
      conditions.push('deleted_at IS NULL');
    }

    if (filter?.tags && filter.tags.length > 0) {
      // Match sources that have ALL specified tags
      // Each tag must be present in the JSON array
      for (const tag of filter.tags) {
        conditions.push(`json_each.value = ?`);
        params.push(tag);
      }
      // Use a subquery approach instead: check each tag is in the array
      // Reset and use a different approach
      conditions.length = 0;
      params.length = 0;

      if (!filter?.includeDeleted) {
        conditions.push('deleted_at IS NULL');
      }

      for (const tag of filter.tags) {
        conditions.push(
          `EXISTS (SELECT 1 FROM json_each(sources.tags) WHERE json_each.value = ?)`,
        );
        params.push(tag);
      }
    }

    if (filter?.since) {
      conditions.push('created_at > ?');
      params.push(filter.since);
    }

    if (filter?.titleSearch) {
      conditions.push("title LIKE ? ESCAPE '\\'");
      const escaped = filter.titleSearch.replace(/[%_\\]/g, '\\$&');
      params.push(`%${escaped}%`);
    }

    let sql = `${selectClause} FROM sources`;

    if (conditions.length > 0) {
      sql += ` WHERE ${conditions.join(' AND ')}`;
    }

    // Only add ORDER BY and LIMIT for non-count queries
    if (!selectClause.includes('COUNT')) {
      sql += ' ORDER BY created_at DESC';

      if (pagination) {
        sql += ' LIMIT ? OFFSET ?';
        params.push(pagination.limit, pagination.offset);
      }
    }

    return { sql, params };
  }
}
