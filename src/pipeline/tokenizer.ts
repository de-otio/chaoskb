/**
 * Token counting for chunking decisions.
 *
 * Uses the real WordPiece tokenizer with the model vocabulary when available,
 * falling back to a lightweight heuristic when the vocab hasn't been loaded.
 */

import { countWordPieceTokens, loadVocabulary, type Vocabulary } from './wordpiece-tokenizer.js';

/** Cached vocabulary reference for token counting. */
let cachedVocab: Vocabulary | null = null;

/**
 * Set the vocabulary for accurate token counting.
 * Call this once after the model/vocab has been downloaded.
 *
 * @param vocabPath - Absolute path to vocab.txt.
 */
export function setTokenizerVocab(vocabPath: string): void {
  cachedVocab = loadVocabulary(vocabPath);
}

/**
 * Clear the tokenizer vocabulary (for testing).
 */
export function clearTokenizerVocab(): void {
  cachedVocab = null;
}

/** Punctuation characters that act as token boundaries (for heuristic fallback). */
const PUNCTUATION_RE = /[\s.,;:!?()\[\]{}'"\-\u2014\u2013\u2026]+/;

/**
 * Approximate multiplier to account for sub-word splitting.
 * WordPiece / BPE tokenizers typically produce ~1.3x the number of
 * whitespace-delimited words.
 */
const SUBWORD_MULTIPLIER = 1.3;

/**
 * Count the number of tokens in a text string.
 *
 * If a vocabulary has been loaded via `setTokenizerVocab()`, returns
 * an accurate WordPiece token count. Otherwise, falls back to the
 * heuristic estimate (suitable for chunking decisions).
 *
 * @param text - The input text to count tokens for.
 * @returns Token count (always >= 0).
 */
export function countTokens(text: string): number {
  if (!text || text.trim().length === 0) {
    return 0;
  }

  if (cachedVocab) {
    return countWordPieceTokens(text, cachedVocab);
  }

  // Heuristic fallback when vocab is not loaded
  const words = text.split(PUNCTUATION_RE).filter((w) => w.length > 0);
  return Math.ceil(words.length * SUBWORD_MULTIPLIER);
}
