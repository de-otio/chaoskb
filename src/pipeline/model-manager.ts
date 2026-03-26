/**
 * ONNX model download and verification manager.
 *
 * Handles downloading the snowflake-arctic-embed-s ONNX model from
 * HuggingFace, verifying its SHA-256 hash, and managing the local
 * model cache directory.
 */

import { createHash } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { access, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import type { DownloadProgressCallback, IModelManager } from './types.js';

/** Default model download URL. */
const MODEL_URL =
  'https://huggingface.co/Snowflake/snowflake-arctic-embed-s/resolve/main/onnx/model.onnx';

/** Vocabulary file download URL. */
const VOCAB_URL =
  'https://huggingface.co/Snowflake/snowflake-arctic-embed-s/resolve/main/vocab.txt';

/** Model filename. */
const MODEL_FILENAME = 'model.onnx';

/** Vocabulary filename. */
const VOCAB_FILENAME = 'vocab.txt';

/** SHA-256 sidecar filename. */
const HASH_FILENAME = 'model.onnx.sha256';

/** Vocabulary SHA-256 sidecar filename. */
const VOCAB_HASH_FILENAME = 'vocab.txt.sha256';

/** Temporary download suffix. */
const TEMP_SUFFIX = '.download';

/**
 * Manages downloading and verifying the ONNX embedding model.
 */
export class ModelManager implements IModelManager {
  private readonly modelsDir: string;

  /**
   * @param modelsDir - Directory to store model files.
   *                    Defaults to `~/.chaoskb/models/`.
   */
  constructor(modelsDir?: string) {
    this.modelsDir = modelsDir ?? join(homedir(), '.chaoskb', 'models');
  }

  /**
   * Get the expected path to the model file.
   */
  getModelPath(): string {
    return join(this.modelsDir, MODEL_FILENAME);
  }

  /**
   * Get the expected path to the vocabulary file.
   */
  getVocabPath(): string {
    return join(this.modelsDir, VOCAB_FILENAME);
  }

  /**
   * Check if the model file exists and its SHA-256 matches the stored hash.
   */
  async isModelReady(): Promise<boolean> {
    const modelPath = this.getModelPath();
    const hashPath = join(this.modelsDir, HASH_FILENAME);

    try {
      await access(modelPath);
      await access(hashPath);
    } catch {
      return false;
    }

    try {
      const storedHash = (await readFile(hashPath, 'utf-8')).trim();
      const actualHash = await computeFileHash(modelPath);
      return storedHash === actualHash;
    } catch {
      return false;
    }
  }

  /**
   * Ensure the model is downloaded and verified. Downloads if missing
   * or hash mismatch. Also downloads the vocabulary file.
   * Returns the path to the model file.
   *
   * @param onProgress - Optional callback for download progress.
   * @returns Absolute path to the verified model file.
   */
  async ensureModel(onProgress?: DownloadProgressCallback): Promise<string> {
    const modelPath = this.getModelPath();

    // Create directory
    await mkdir(this.modelsDir, { recursive: true });

    // Ensure vocab is downloaded (small file, do first)
    await this.ensureVocab();

    if (await this.isModelReady()) {
      return modelPath;
    }

    // Download to temporary file
    const tempPath = modelPath + TEMP_SUFFIX;
    await this.downloadModel(tempPath, onProgress);

    // Compute hash
    const hash = await computeFileHash(tempPath);

    // Move to final location
    await rename(tempPath, modelPath);

    // Write hash sidecar
    await writeFile(join(this.modelsDir, HASH_FILENAME), hash + '\n', 'utf-8');

    return modelPath;
  }

  /**
   * Check if the vocabulary file exists and its hash matches.
   */
  async isVocabReady(): Promise<boolean> {
    const vocabPath = this.getVocabPath();
    const hashPath = join(this.modelsDir, VOCAB_HASH_FILENAME);

    try {
      await access(vocabPath);
      await access(hashPath);
    } catch {
      return false;
    }

    try {
      const storedHash = (await readFile(hashPath, 'utf-8')).trim();
      const actualHash = await computeFileHash(vocabPath);
      return storedHash === actualHash;
    } catch {
      return false;
    }
  }

  /**
   * Ensure the vocabulary file is downloaded and verified.
   */
  async ensureVocab(): Promise<string> {
    const vocabPath = this.getVocabPath();

    if (await this.isVocabReady()) {
      return vocabPath;
    }

    await mkdir(this.modelsDir, { recursive: true });

    const tempPath = vocabPath + TEMP_SUFFIX;
    await this.downloadFile(VOCAB_URL, tempPath);

    const hash = await computeFileHash(tempPath);
    await rename(tempPath, vocabPath);
    await writeFile(join(this.modelsDir, VOCAB_HASH_FILENAME), hash + '\n', 'utf-8');

    return vocabPath;
  }

  /**
   * Download the model file with progress reporting.
   */
  private async downloadModel(
    destPath: string,
    onProgress?: DownloadProgressCallback,
  ): Promise<void> {
    return this.downloadFile(MODEL_URL, destPath, onProgress);
  }

  /**
   * Download a file from a URL with optional progress reporting and resume support.
   */
  private async downloadFile(
    url: string,
    destPath: string,
    onProgress?: DownloadProgressCallback,
  ): Promise<void> {
    // Check for existing partial download for potential resume
    let existingSize = 0;
    try {
      const { stat } = await import('node:fs/promises');
      const stats = await stat(destPath);
      existingSize = stats.size;
    } catch {
      // No partial download exists
    }

    const headers: Record<string, string> = {
      'User-Agent': 'ChaosKB/0.1',
    };

    // Attempt resume if partial file exists
    if (existingSize > 0) {
      headers['Range'] = `bytes=${existingSize}-`;
    }

    let response: Response;
    try {
      response = await fetch(url, { headers, redirect: 'follow' });
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      throw new Error(`Failed to download ${url}: ${msg}`);
    }

    // If server doesn't support range or returned full content, start fresh
    if (response.status === 200) {
      existingSize = 0;
    } else if (response.status === 206) {
      // Partial content — resume supported
    } else if (!response.ok) {
      throw new Error(`Failed to download ${url}: HTTP ${response.status} ${response.statusText}`);
    }

    const contentLength = response.headers.get('content-length');
    const totalSize = contentLength
      ? existingSize + parseInt(contentLength, 10)
      : 0;

    if (!response.body) {
      throw new Error('Response body is null');
    }

    // Convert web ReadableStream to Node.js Readable
    const nodeStream = Readable.fromWeb(response.body as import('node:stream/web').ReadableStream);

    const writeStream = createWriteStream(destPath, {
      flags: existingSize > 0 && response.status === 206 ? 'a' : 'w',
    });

    let downloaded = existingSize;

    nodeStream.on('data', (chunk: Buffer) => {
      downloaded += chunk.length;
      onProgress?.(downloaded, totalSize);
    });

    try {
      await pipeline(nodeStream, writeStream);
    } catch (error: unknown) {
      // Clean up partial download on error
      try {
        await unlink(destPath);
      } catch {
        // Ignore cleanup errors
      }
      const msg = error instanceof Error ? error.message : String(error);
      throw new Error(`Download interrupted: ${msg}`);
    }
  }
}

/**
 * Compute the SHA-256 hash of a file.
 *
 * @param filePath - Path to the file.
 * @returns Hex-encoded SHA-256 hash string.
 */
async function computeFileHash(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}
