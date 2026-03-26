/** Sync configuration */
export interface SyncConfig {
  /** Server endpoint URL (must be HTTPS) */
  endpoint: string;
  /** Path to SSH private key (fallback if ssh-agent unavailable) */
  sshKeyPath?: string;
}

/** Sync state persisted between syncs */
export interface SyncState {
  /** ISO 8601 timestamp of last successful sync */
  lastSyncTimestamp?: string;
  /** Cursor for resuming paginated full sync */
  fullSyncCursor?: string;
  /** Whether a full sync is in progress */
  fullSyncInProgress: boolean;
}

/** Result of a sync operation */
export interface SyncResult {
  /** Number of new blobs downloaded */
  newBlobs: number;
  /** Number of updated blobs */
  updatedBlobs: number;
  /** Number of tombstones processed */
  deletedBlobs: number;
  /** Conflicts detected and resolved */
  conflicts: SyncConflict[];
  /** Errors encountered (non-fatal) */
  errors: SyncError[];
  /** Whether sync completed successfully */
  success: boolean;
}

/** A sync conflict that was detected and resolved */
export interface SyncConflict {
  blobId: string;
  /** How the conflict was resolved */
  resolution: 'local_wins' | 'remote_wins' | 'keep_both';
  /** Why a conflict was detected */
  reason: string;
  /** Timestamp of local version */
  localTimestamp?: string;
  /** Timestamp of remote version */
  remoteTimestamp?: string;
}

/** Sync error */
export interface SyncError {
  blobId?: string;
  message: string;
  code: string;
  retryable: boolean;
}

/** Blob metadata from server */
export interface BlobMetadata {
  id: string;
  size: number;
  ts: string;
}

/** Tombstone from server */
export interface Tombstone {
  id: string;
  deletedAt: string;
}

/** Server list response */
export interface BlobListResponse {
  blobs: BlobMetadata[];
  tombstones: Tombstone[];
}

/** Upload queue item */
export interface UploadQueueItem {
  blobId: string;
  data: Uint8Array;
  retryCount: number;
  lastAttempt?: string;
  error?: string;
}

/** Quota information from server */
export interface QuotaInfo {
  /** Bytes used */
  used: number;
  /** Bytes allowed */
  limit: number;
  /** Usage percentage (0-100) */
  percentage: number;
}

/** Sync service interface */
export interface ISyncService {
  /** Run incremental sync (download changes since last sync) */
  incrementalSync(): Promise<SyncResult>;
  /** Run full sync (download all blobs) */
  fullSync(): Promise<SyncResult>;
  /** Upload a blob to the server */
  upload(blobId: string, data: Uint8Array): Promise<void>;
  /** Get current quota usage */
  getQuota(): Promise<QuotaInfo>;
  /** Write and verify canary blob */
  verifyCanary(): Promise<boolean>;
  /** Verify blob count matches server */
  verifyCount(localCount: number): Promise<boolean>;
}

/** HTTP client for server communication */
export interface ISyncHttpClient {
  get(path: string): Promise<Response>;
  put(path: string, body: Uint8Array): Promise<Response>;
  delete(path: string): Promise<Response>;
  post(path: string, body?: Uint8Array): Promise<Response>;
}
