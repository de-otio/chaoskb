/**
 * Local file content extraction.
 *
 * Dispatches to format-specific extractors based on file extension.
 * Supports PDF, DOCX, PPTX, HTML, TXT, and Markdown.
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import type { ExtractedContent } from './types.js';

// ===== Supported formats ===================================================

const EXTENSION_MAP: Record<string, string> = {
  '.pdf': 'pdf',
  '.docx': 'docx',
  '.pptx': 'pptx',
  '.html': 'html',
  '.htm': 'html',
  '.txt': 'txt',
  '.md': 'md',
  '.markdown': 'md',
};

const SUPPORTED_EXTENSIONS = Object.keys(EXTENSION_MAP).join(', ');

// ===== Limits ==============================================================

/** Maximum file size in bytes (50 MB). */
const MAX_FILE_SIZE = 50 * 1024 * 1024;

/** Maximum total uncompressed size for ZIP-based formats (100 MB). */
const MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024;

// ===== Public API ==========================================================

/**
 * Extract content from a local file.
 *
 * @param filePath - Path to the file (resolved to absolute).
 * @returns Extracted content with title, text, and the absolute path as `url`.
 * @throws On missing/unreadable file, unsupported format, or empty content.
 */
export async function extractFromFile(filePath: string): Promise<ExtractedContent> {
  // Check extension first for a clear error on unsupported formats
  const ext = path.extname(filePath).toLowerCase();
  const format = EXTENSION_MAP[ext];
  if (!format) {
    throw new Error(
      `Unsupported file format "${ext}". Supported formats: ${SUPPORTED_EXTENSIONS}`,
    );
  }

  const absPath = path.resolve(filePath);

  // Resolve symlinks to get the real path, then re-check the extension
  let realPath: string;
  try {
    realPath = await fs.realpath(absPath);
  } catch {
    throw new Error(`File not found or not readable: ${path.basename(filePath)}`);
  }

  const realExt = path.extname(realPath).toLowerCase();
  if (!EXTENSION_MAP[realExt]) {
    throw new Error(
      `Symlink target has unsupported extension "${realExt}". Supported formats: ${SUPPORTED_EXTENSIONS}`,
    );
  }

  // Check file is regular and within size limit
  const stat = await fs.stat(realPath);
  if (!stat.isFile()) {
    throw new Error('Path is not a regular file.');
  }
  if (stat.size > MAX_FILE_SIZE) {
    throw new Error(
      `File is too large (${(stat.size / 1024 / 1024).toFixed(1)} MB). Maximum supported size is ${MAX_FILE_SIZE / 1024 / 1024} MB.`,
    );
  }

  switch (format) {
    case 'pdf':
      return extractPdf(realPath);
    case 'docx':
      return extractDocx(realPath);
    case 'pptx':
      return extractPptx(realPath);
    case 'html':
      return extractHtmlFile(realPath);
    case 'txt':
    case 'md':
      return extractPlainText(realPath);
    default:
      throw new Error(`Unsupported format: ${format}`);
  }
}

// ===== Format extractors ===================================================

async function extractPdf(filePath: string): Promise<ExtractedContent> {
  const { PDFParse } = await import('pdf-parse');
  const buffer = await fs.readFile(filePath);
  const uint8 = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  const parser = new PDFParse({ data: uint8, isEvalSupported: false });
  const textResult = await parser.getText();
  // Strip the page footer markers ("-- N of M --")
  const rawText = textResult.text.replace(/\n-- \d+ of \d+ --\n/g, '\n');
  const content = cleanText(rawText);

  if (content.length === 0) {
    throw new Error(
      'No extractable text in PDF. The file may be a scanned document without OCR.',
    );
  }

  const infoResult = await parser.getInfo();
  const title = infoResult?.info?.Title || filenameTitle(filePath);
  parser.destroy();

  return {
    title,
    content,
    url: filePath,
    byteLength: Buffer.byteLength(content, 'utf-8'),
  };
}

async function extractDocx(filePath: string): Promise<ExtractedContent> {
  const mammoth = await import('mammoth');
  const result = await mammoth.convertToHtml({ path: filePath });

  if (!result.value || result.value.trim().length === 0) {
    throw new Error('No extractable content in DOCX file.');
  }

  // Pipe the clean HTML through existing Readability extraction
  const { extractContent } = await import('./extract.js');
  try {
    const extracted = extractContent(result.value, filePath);
    return {
      ...extracted,
      url: filePath,
      title: extracted.title || filenameTitle(filePath),
    };
  } catch {
    // If Readability fails (e.g. very simple doc), fall back to plain text
    const text = cleanText(result.value.replace(/<[^>]+>/g, ' '));
    if (text.length === 0) {
      throw new Error('No extractable content in DOCX file.');
    }
    return {
      title: filenameTitle(filePath),
      content: text,
      url: filePath,
      byteLength: Buffer.byteLength(text, 'utf-8'),
    };
  }
}

async function extractPptx(filePath: string): Promise<ExtractedContent> {
  const JSZip = (await import('jszip')).default;
  const buffer = await fs.readFile(filePath);
  const zip = await JSZip.loadAsync(buffer);

  // Find slide XML files and sort by slide number
  const slideFiles = Object.keys(zip.files)
    .filter((name) => /^ppt\/slides\/slide\d+\.xml$/.test(name))
    .sort((a, b) => {
      const numA = parseInt(a.match(/slide(\d+)/)?.[1] ?? '0');
      const numB = parseInt(b.match(/slide(\d+)/)?.[1] ?? '0');
      return numA - numB;
    });

  if (slideFiles.length === 0) {
    throw new Error('No slides found in PPTX file.');
  }

  // Decompress slides incrementally, tracking actual bytes to guard against zip bombs
  const slideTexts: string[] = [];
  let firstSlideTitle = '';
  let totalDecompressed = 0;

  for (const slideFile of slideFiles) {
    const bytes = await zip.file(slideFile)!.async('uint8array');
    totalDecompressed += bytes.byteLength;
    if (totalDecompressed > MAX_UNCOMPRESSED_SIZE) {
      throw new Error(
        `PPTX uncompressed content exceeds ${MAX_UNCOMPRESSED_SIZE / 1024 / 1024} MB limit.`,
      );
    }
    const xml = new TextDecoder().decode(bytes);
    const text = extractSlideText(xml);
    if (text) {
      slideTexts.push(text);
      if (!firstSlideTitle) {
        firstSlideTitle = text.split('\n')[0].trim();
      }
    }
  }

  const content = cleanText(slideTexts.join('\n\n'));
  if (content.length === 0) {
    throw new Error('No extractable text in PPTX file.');
  }

  return {
    title: firstSlideTitle || filenameTitle(filePath),
    content,
    url: filePath,
    byteLength: Buffer.byteLength(content, 'utf-8'),
  };
}

async function extractHtmlFile(filePath: string): Promise<ExtractedContent> {
  const html = await fs.readFile(filePath, 'utf-8');
  const { extractContent } = await import('./extract.js');
  const extracted = extractContent(html, filePath);
  return {
    ...extracted,
    url: filePath,
    title: extracted.title || filenameTitle(filePath),
  };
}

async function extractPlainText(filePath: string): Promise<ExtractedContent> {
  const raw = await fs.readFile(filePath, 'utf-8');
  const content = cleanText(raw);

  if (content.length === 0) {
    throw new Error('Empty file.');
  }

  // Title: first markdown heading, or first short line, or filename
  let title = '';
  const headingMatch = content.match(/^#\s+(.+)$/m);
  if (headingMatch) {
    title = headingMatch[1].trim();
  } else {
    const firstLine = content.split('\n').find((l) => l.trim().length > 0);
    if (firstLine && firstLine.length < 120) {
      title = firstLine.trim();
    }
  }

  return {
    title: title || filenameTitle(filePath),
    content,
    url: filePath,
    byteLength: Buffer.byteLength(content, 'utf-8'),
  };
}

// ===== Utilities ===========================================================

/**
 * Extract text from a PPTX slide XML string.
 * Groups by `<a:p>` paragraphs, collects `<a:t>` text runs within each.
 */
function extractSlideText(xml: string): string {
  const paragraphs: string[] = [];
  const pRegex = /<a:p\b[^>]*>([\s\S]*?)<\/a:p>/g;
  const tRegex = /<a:t>([\s\S]*?)<\/a:t>/g;

  let pMatch;
  while ((pMatch = pRegex.exec(xml)) !== null) {
    const pContent = pMatch[1];
    const texts: string[] = [];
    let tMatch;
    tRegex.lastIndex = 0;
    while ((tMatch = tRegex.exec(pContent)) !== null) {
      texts.push(tMatch[1]);
    }
    if (texts.length > 0) {
      paragraphs.push(texts.join(''));
    }
  }

  return paragraphs.join('\n');
}

/** Extract a readable title from a file path (filename without extension). */
function filenameTitle(filePath: string): string {
  return path.basename(filePath, path.extname(filePath));
}

/** Clean extracted text: strip steganographic chars, collapse whitespace, trim lines. */
function cleanText(text: string): string {
  return text
    .replace(/[\u2028\u2029]/g, '\n')                                // Unicode line/paragraph separators → newline
    .replace(/[\u200B-\u200F\u202A-\u202F\u2060-\u206F\uFEFF]/g, '') // strip zero-width / bidi / invisible chars
    .replace(/[\t ]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/^ +| +$/gm, '')
    .trim();
}
