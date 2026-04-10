/** Source record in the database */
export interface SourceRecord {
  id: string;
  url: string;
  title: string;
  tags: string[];
  chunkCount: number;
  blobSizeBytes: number;
  createdAt: string;
  updatedAt: string;
  lastAccessedAt: string;
  deletedAt?: string;
}

/** Chunk record in the database */
export interface ChunkRecord {
  id: string;
  sourceId: string;
  chunkIndex: number;
  content: string;
  embedding: Float32Array;
  tokenCount: number;
  model: string;
}

/** Sync status for a blob */
export enum SyncStatus {
  LocalOnly = 'local_only',
  Synced = 'synced',
  PendingDelete = 'pending_delete',
  SyncFailed = 'sync_failed',
}

/** Sync status record */
export interface SyncStatusRecord {
  blobId: string;
  status: SyncStatus;
  lastAttempt?: string;
  errorMessage?: string;
}

/** Pagination options */
export interface PaginationOptions {
  limit: number;
  offset: number;
}

/** Filter options for listing sources */
export interface SourceFilter {
  tags?: string[];
  /** Only include sources created after this date */
  since?: string;
  /** Search title substring */
  titleSearch?: string;
  /** Include soft-deleted sources */
  includeDeleted?: boolean;
}

/** Database configuration */
export interface DatabaseConfig {
  /** Path to the SQLite database file */
  path: string;
  /** Project name (undefined for personal KB) */
  projectName?: string;
}

/** Source repository interface */
export interface ISourceRepository {
  insert(source: Omit<SourceRecord, 'createdAt' | 'updatedAt' | 'lastAccessedAt'>): SourceRecord;
  getById(id: string): SourceRecord | null;
  getByUrl(url: string): SourceRecord | null;
  list(filter?: SourceFilter, pagination?: PaginationOptions): SourceRecord[];
  count(filter?: SourceFilter): number;
  softDelete(id: string): boolean;
  restore(id: string): boolean;
  updateLastAccessed(id: string): void;
}

/** Result of a keyword search */
export interface KeywordSearchResult {
  sourceId: string;
  chunkIndex: number;
  content: string;
  snippet: string;
  rank: number;
}

/** Chunk repository interface */
export interface IChunkRepository {
  insertMany(chunks: Omit<ChunkRecord, 'id'>[]): ChunkRecord[];
  getBySourceId(sourceId: string): ChunkRecord[];
  deleteBySourceId(sourceId: string): number;
  /** Search chunk content using FTS5 keyword matching */
  searchKeyword(query: string, topK: number): KeywordSearchResult[];
}

/** Sync status repository interface */
export interface ISyncStatusRepository {
  set(blobId: string, status: SyncStatus, errorMessage?: string): void;
  get(blobId: string): SyncStatusRecord | null;
  getPending(): SyncStatusRecord[];
  getByStatus(status: SyncStatus): SyncStatusRecord[];
}

/** Embedding index for in-memory search */
export interface IEmbeddingIndex {
  /** Load all embeddings from database */
  load(): void;
  /** Add embeddings for a source */
  add(sourceId: string, chunks: { chunkIndex: number; embedding: Float32Array }[]): void;
  /** Remove embeddings for a source */
  remove(sourceId: string): void;
  /** Search for similar embeddings, return indices sorted by score */
  search(
    query: Float32Array,
    topK: number,
  ): { sourceId: string; chunkIndex: number; score: number }[];
  /** Total number of embeddings in the index */
  readonly size: number;
}

/** Database manager for multiple KBs */
export interface IDatabaseManager {
  /** Get or create the personal database */
  getPersonalDb(): IDatabase;
  /** Get or create a project database */
  getProjectDb(projectName: string): IDatabase;
  /** Get or create a named KB database (from ~/.chaoskb/<name>/db/) */
  getNamedKBDb(kbName: string): IDatabase;
  /** List all project databases */
  listProjects(): { name: string; path: string; sizeBytes: number; sourceCount: number }[];
  /** Delete a project database */
  deleteProject(projectName: string): boolean;
  /** Close all open databases */
  closeAll(): void;
}

/** Sync queue item */
export interface SyncQueueItem {
  id: number;
  blobId: string;
  operation: 'upload' | 'delete';
  data: Uint8Array | null;
  retryCount: number;
  maxRetries: number;
  lastAttempt?: string;
  nextAttempt?: string;
  errorMessage?: string;
  status: 'pending' | 'processing' | 'failed' | 'completed';
  createdAt: string;
}

/** Sync queue repository — SQLite-backed, multi-process safe */
export interface ISyncQueueRepository {
  /** Enqueue an upload or delete. Replaces existing pending entry for same blob+operation. */
  enqueue(blobId: string, operation: 'upload' | 'delete', data?: Uint8Array): void;
  /** Atomically claim pending items for processing. Each item is claimed by exactly one process. */
  claimBatch(limit: number): SyncQueueItem[];
  /** Mark an item as completed (deletes from queue). */
  complete(id: number): void;
  /** Mark an item as failed with error, increment retry count, set exponential backoff. */
  fail(id: number, error: string): void;
  /** Mark an item as permanently failed (exceeded max retries). */
  permanentFail(id: number, error: string): void;
  /** Release stale 'processing' items back to 'pending' (crash recovery). */
  releaseStale(olderThanSeconds: number): number;
  /** Count of pending + processing items. */
  pendingCount(): number;
}

/** Atomic sequence counter — SQLite-backed, multi-process safe */
export interface ISyncSequenceRepository {
  /** Atomically increment and return the new value. */
  next(): number;
  /** Get current value without incrementing. */
  peek(): number;
}

/** Key-value sync state store — SQLite-backed */
export interface ISyncStateRepository {
  get(key: string): string | undefined;
  set(key: string, value: string): void;
  delete(key: string): void;
}

/** Combined database interface */
export interface IDatabase {
  readonly sources: ISourceRepository;
  readonly chunks: IChunkRepository;
  readonly syncStatus: ISyncStatusRepository;
  readonly embeddingIndex: IEmbeddingIndex;
  readonly syncQueue: ISyncQueueRepository;
  readonly syncSequence: ISyncSequenceRepository;
  readonly syncState: ISyncStateRepository;
  /** Enqueue an encrypted blob for upload. Sets sync status to local_only. */
  storeAndEnqueueUpload(blobId: string, encryptedBytes: Uint8Array): void;
  /** Enqueue a blob for deletion from the sync server. Sets sync status to pending_delete. */
  enqueueDelete(blobId: string): void;
  close(): void;
}
