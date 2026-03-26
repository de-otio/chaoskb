/** Configuration for the content pipeline */
export interface PipelineConfig {
  /** Path to ONNX model directory (default: ~/.chaoskb/models/) */
  modelPath: string;
  /** Maximum tokens per chunk (default: 500) */
  maxChunkTokens: number;
  /** Token overlap between chunks (default: 50) */
  overlapTokens: number;
  /** HTTP request timeout in ms (default: 30000) */
  fetchTimeoutMs: number;
  /** Maximum redirects to follow (default: 5) */
  maxRedirects: number;
  /** User-Agent header */
  userAgent: string;
}

/** Extracted content from a URL */
export interface ExtractedContent {
  title: string;
  content: string;
  /** Original URL */
  url: string;
  /** Byte length of extracted content */
  byteLength: number;
}

/** A text chunk from extracted content */
export interface Chunk {
  /** Chunk text content */
  content: string;
  /** Zero-based index within the source */
  index: number;
  /** Approximate token count */
  tokenCount: number;
  /** Byte offset in original extracted text */
  byteOffset: number;
}

/** Embedding vector (384-dimensional for snowflake-arctic-embed-s) */
export type EmbeddingVector = Float32Array;

/** A chunk with its computed embedding */
export interface EmbeddedChunk extends Chunk {
  /** 384-dimensional embedding vector */
  embedding: EmbeddingVector;
  /** Model identifier: "snowflake-arctic-embed-s@384" */
  model: string;
}

/** Search result from the embedding index */
export interface SearchResult {
  /** Source blob ID */
  sourceId: string;
  /** Chunk index within the source */
  chunkIndex: number;
  /** Chunk text content */
  content: string;
  /** Cosine similarity score (0-1) */
  score: number;
}

/** Model download progress callback */
export type DownloadProgressCallback = (downloaded: number, total: number) => void;

/** Content pipeline service interface */
export interface IContentPipeline {
  /** Fetch and extract content from a URL */
  fetchAndExtract(url: string): Promise<ExtractedContent>;
  /** Split extracted text into chunks */
  chunk(text: string): Chunk[];
  /** Embed a single text string */
  embed(text: string): Promise<EmbeddingVector>;
  /** Embed multiple chunks */
  embedChunks(chunks: Chunk[]): Promise<EmbeddedChunk[]>;
  /** Search embeddings for similar content */
  search(query: EmbeddingVector, embeddings: EmbeddingVector[], topK: number): number[];
}

/** Model manager for downloading and verifying the ONNX model */
export interface IModelManager {
  /** Check if model is downloaded and verified */
  isModelReady(): Promise<boolean>;
  /** Download model if not present, verify SHA-256. Also downloads vocab. */
  ensureModel(onProgress?: DownloadProgressCallback): Promise<string>;
  /** Get path to model file */
  getModelPath(): string;
  /** Get path to vocabulary file */
  getVocabPath(): string;
  /** Check if vocabulary is downloaded and verified */
  isVocabReady(): Promise<boolean>;
  /** Download vocabulary if not present, verify SHA-256 */
  ensureVocab(): Promise<string>;
}
