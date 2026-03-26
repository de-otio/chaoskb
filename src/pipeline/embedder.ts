/**
 * ONNX Runtime embedding using snowflake-arctic-embed-s.
 *
 * Provides a high-level Embedder class that loads an ONNX model and
 * produces 384-dimensional embedding vectors from text input.
 *
 * Uses a real BERT WordPiece tokenizer with the model's vocabulary
 * for proper subword tokenization and meaningful embeddings.
 */

import * as ort from 'onnxruntime-node';
import type { EmbeddingVector } from './types.js';
import { loadVocabulary, tokenize, type Vocabulary } from './wordpiece-tokenizer.js';

/** Maximum sequence length for the model. */
const MAX_SEQ_LENGTH = 512;

/**
 * Embedder wraps an ONNX inference session for producing text embeddings.
 */
export class Embedder {
  private session: ort.InferenceSession | null = null;
  private vocab: Vocabulary | null = null;
  readonly modelPath: string;
  private readonly vocabPath: string;

  /**
   * @param modelPath - Absolute path to the ONNX model file.
   * @param vocabPath - Absolute path to the vocab.txt file.
   */
  constructor(modelPath: string, vocabPath?: string) {
    this.modelPath = modelPath;
    // Default: vocab.txt in the same directory as the model
    this.vocabPath = vocabPath ?? modelPath.replace(/[^/\\]+$/, 'vocab.txt');
  }

  /**
   * Load the ONNX model into memory. Called lazily on first embed() call,
   * but can be called explicitly to pre-warm.
   */
  async initialize(): Promise<void> {
    if (this.session) {
      return;
    }

    try {
      this.session = await ort.InferenceSession.create(this.modelPath, {
        executionProviders: ['cpu'],
      });
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Failed to load ONNX model at ${this.modelPath}: ${msg}. ` +
          'Ensure the model file exists and is a valid ONNX model.',
      );
    }

    // Load vocabulary
    this.vocab = loadVocabulary(this.vocabPath);
  }

  /**
   * Embed a single text string into a 384-dimensional vector.
   *
   * @param text - The text to embed.
   * @param prefix - Optional prefix (e.g., "query: " for search queries).
   * @returns A Float32Array of 384 dimensions.
   */
  async embed(text: string, prefix?: string): Promise<EmbeddingVector> {
    const results = await this.embedBatch([prefix ? `${prefix}${text}` : text]);
    return results[0];
  }

  /**
   * Embed multiple texts in a single batch.
   *
   * @param texts - Array of text strings to embed.
   * @returns Array of Float32Array embeddings, one per input text.
   */
  async embedBatch(texts: string[]): Promise<EmbeddingVector[]> {
    if (!this.session) {
      await this.initialize();
    }

    const session = this.session!;
    const vocab = this.vocab!;
    const batchSize = texts.length;

    // Tokenize each text into input IDs using real WordPiece tokenizer
    const allInputIds: bigint[][] = [];
    const allAttentionMask: bigint[][] = [];
    let maxLen = 0;

    for (const text of texts) {
      const ids = tokenize(text, vocab, MAX_SEQ_LENGTH);
      allInputIds.push(ids);
      allAttentionMask.push(ids.map(() => 1n));
      maxLen = Math.max(maxLen, ids.length);
    }

    // Pad to uniform length
    for (let i = 0; i < batchSize; i++) {
      while (allInputIds[i].length < maxLen) {
        allInputIds[i].push(0n); // PAD token
        allAttentionMask[i].push(0n);
      }
    }

    // Flatten into typed arrays
    const inputIdsFlat = new BigInt64Array(batchSize * maxLen);
    const attentionMaskFlat = new BigInt64Array(batchSize * maxLen);

    for (let i = 0; i < batchSize; i++) {
      for (let j = 0; j < maxLen; j++) {
        inputIdsFlat[i * maxLen + j] = allInputIds[i][j];
        attentionMaskFlat[i * maxLen + j] = allAttentionMask[i][j];
      }
    }

    // Create ONNX tensors
    const feeds: Record<string, ort.Tensor> = {
      input_ids: new ort.Tensor('int64', inputIdsFlat, [batchSize, maxLen]),
      attention_mask: new ort.Tensor('int64', attentionMaskFlat, [batchSize, maxLen]),
    };

    // Some models expect token_type_ids
    const inputNames = session.inputNames;
    if (inputNames.includes('token_type_ids')) {
      const tokenTypeIds = new BigInt64Array(batchSize * maxLen); // all zeros
      feeds['token_type_ids'] = new ort.Tensor('int64', tokenTypeIds, [batchSize, maxLen]);
    }

    // Run inference
    const results = await session.run(feeds);

    // Extract embeddings from output
    // The model may output under various names; try common ones
    const outputKey =
      results['sentence_embedding'] ? 'sentence_embedding' :
      results['last_hidden_state'] ? 'last_hidden_state' :
      Object.keys(results)[0];

    const outputTensor = results[outputKey];
    const outputData = outputTensor.data as Float32Array;
    const outputDims = outputTensor.dims as readonly number[];

    // If output is [batch, seq_len, dim], mean-pool over seq_len
    // If output is [batch, dim], use directly
    const embeddings: EmbeddingVector[] = [];

    if (outputDims.length === 3) {
      // [batch, seq_len, dim] — mean pooling with attention mask
      const seqLen = outputDims[1] as number;
      const dim = outputDims[2] as number;

      for (let b = 0; b < batchSize; b++) {
        const embedding = new Float32Array(dim);
        let tokenCount = 0;

        for (let s = 0; s < seqLen; s++) {
          if (allAttentionMask[b][s] === 1n) {
            tokenCount++;
            for (let d = 0; d < dim; d++) {
              embedding[d] += outputData[b * seqLen * dim + s * dim + d];
            }
          }
        }

        // Average
        if (tokenCount > 0) {
          for (let d = 0; d < dim; d++) {
            embedding[d] /= tokenCount;
          }
        }

        // L2 normalize
        embeddings.push(l2Normalize(embedding));
      }
    } else if (outputDims.length === 2) {
      // [batch, dim] — already pooled
      const dim = outputDims[1] as number;
      for (let b = 0; b < batchSize; b++) {
        const embedding = new Float32Array(dim);
        for (let d = 0; d < dim; d++) {
          embedding[d] = outputData[b * dim + d];
        }
        embeddings.push(l2Normalize(embedding));
      }
    } else {
      throw new Error(`Unexpected output tensor shape: [${outputDims.join(', ')}]`);
    }

    return embeddings;
  }

  /**
   * Release the ONNX session and free memory.
   */
  dispose(): void {
    if (this.session) {
      // InferenceSession doesn't have a sync dispose in all versions;
      // release is best-effort.
      this.session.release?.();
      this.session = null;
    }
  }
}

/**
 * L2-normalize a vector in place and return it.
 */
function l2Normalize(vec: Float32Array): Float32Array {
  let sumSq = 0;
  for (let i = 0; i < vec.length; i++) {
    sumSq += vec[i] * vec[i];
  }
  const norm = Math.sqrt(sumSq);
  if (norm > 0) {
    for (let i = 0; i < vec.length; i++) {
      vec[i] /= norm;
    }
  }
  return vec;
}
