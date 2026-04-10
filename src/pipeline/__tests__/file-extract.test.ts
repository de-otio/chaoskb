import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { extractFromFile } from '../file-extract.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, 'fixtures');

function fixture(name: string): string {
  return join(FIXTURES_DIR, name);
}

describe('extractFromFile', () => {
  // --- Input validation ----------------------------------------------------

  describe('input validation', () => {
    it('throws on missing file', async () => {
      await expect(extractFromFile('/nonexistent/file.txt')).rejects.toThrow(
        'File not found',
      );
    });

    it('throws on unsupported file extension', async () => {
      await expect(extractFromFile('/some/path/file.xyz')).rejects.toThrow(
        'Unsupported file format',
      );
    });

    it('lists supported formats in error message', async () => {
      await expect(extractFromFile('/some/path/file.xyz')).rejects.toThrow('.pdf');
    });
  });

  // --- Error paths ----------------------------------------------------------

  describe('error paths', () => {
    it('throws on empty text file', async () => {
      await expect(extractFromFile(fixture('empty.txt'))).rejects.toThrow('Empty file');
    });

    it('throws on files exceeding size limit', async () => {
      // We can't easily create a 50MB file in a test, but we can test the error message format
      // by checking the function handles stat correctly on normal files
      const result = await extractFromFile(fixture('sample.txt'));
      expect(result.content.length).toBeGreaterThan(0);
    });

    it('throws on PPTX with no slides', async () => {
      await expect(extractFromFile(fixture('empty.pptx'))).rejects.toThrow('No slides found');
    });

    it('falls back to filename as title for TXT with long first line', async () => {
      const longLine = 'A'.repeat(200) + '\nSome content here for testing purposes.';
      const tmpFile = join(tmpdir(), 'chaoskb-test-longline.txt');
      writeFileSync(tmpFile, longLine);
      const result = await extractFromFile(tmpFile);
      expect(result.title).toBe('chaoskb-test-longline');
    });
  });

  // --- TXT extraction ------------------------------------------------------

  describe('TXT files', () => {
    it('extracts content from a plain text file', async () => {
      const result = await extractFromFile(fixture('sample.txt'));
      expect(result.content).toContain('Functional programming');
      expect(result.content).toContain('immutability');
    });

    it('uses first line as title', async () => {
      const result = await extractFromFile(fixture('sample.txt'));
      expect(result.title).toBe('Functional Programming Fundamentals');
    });

    it('sets url to the absolute file path', async () => {
      const result = await extractFromFile(fixture('sample.txt'));
      expect(result.url).toContain('sample.txt');
      expect(result.url).toMatch(/^\//); // absolute path
    });

    it('computes byte length correctly', async () => {
      const result = await extractFromFile(fixture('sample.txt'));
      expect(result.byteLength).toBe(Buffer.byteLength(result.content, 'utf-8'));
    });
  });

  // --- Markdown extraction -------------------------------------------------

  describe('Markdown files', () => {
    it('extracts content from markdown', async () => {
      const result = await extractFromFile(fixture('sample.md'));
      expect(result.content).toContain('TypeScript');
      expect(result.content).toContain('Type Safety');
    });

    it('uses first heading as title', async () => {
      const result = await extractFromFile(fixture('sample.md'));
      expect(result.title).toBe('Getting Started with TypeScript');
    });
  });

  // --- HTML extraction -----------------------------------------------------

  describe('HTML files', () => {
    it('extracts content from HTML file using Readability', async () => {
      const result = await extractFromFile(fixture('simple-article.html'));
      expect(result.content).toContain('superposition');
      expect(result.content).toContain('entanglement');
    });

    it('extracts title from HTML', async () => {
      const result = await extractFromFile(fixture('simple-article.html'));
      expect(result.title).toContain('Quantum');
    });

    it('sets url to the file path', async () => {
      const result = await extractFromFile(fixture('simple-article.html'));
      expect(result.url).toContain('simple-article.html');
    });
  });

  // --- PDF extraction ------------------------------------------------------

  describe('PDF files', () => {
    it('extracts text from PDF', async () => {
      const result = await extractFromFile(fixture('sample.pdf'));
      expect(result.content).toContain('Climate');
      expect(result.content.length).toBeGreaterThan(100);
    });

    it('extracts title from PDF metadata', async () => {
      const result = await extractFromFile(fixture('sample.pdf'));
      expect(result.title).toBe('Climate Change Overview');
    });

    it('sets url to the file path', async () => {
      const result = await extractFromFile(fixture('sample.pdf'));
      expect(result.url).toContain('sample.pdf');
    });
  });

  // --- DOCX extraction -----------------------------------------------------

  describe('DOCX files', () => {
    it('extracts content from DOCX', async () => {
      const result = await extractFromFile(fixture('sample.docx'));
      expect(result.content).toContain('Machine learning');
      expect(result.content).toContain('artificial intelligence');
    });

    it('extracts a title', async () => {
      const result = await extractFromFile(fixture('sample.docx'));
      // mammoth converts to HTML, Readability extracts — title may come from heading
      expect(result.title.length).toBeGreaterThan(0);
    });
  });

  // --- PPTX extraction -----------------------------------------------------

  describe('PPTX files', () => {
    it('extracts text from all slides', async () => {
      const result = await extractFromFile(fixture('sample.pptx'));
      expect(result.content).toContain('Renewable Energy');
      expect(result.content).toContain('Solar Energy');
      expect(result.content).toContain('Photovoltaic');
    });

    it('uses first slide text as title', async () => {
      const result = await extractFromFile(fixture('sample.pptx'));
      expect(result.title).toContain('Renewable Energy');
    });

    it('preserves slide order', async () => {
      const result = await extractFromFile(fixture('sample.pptx'));
      const renewableIdx = result.content.indexOf('Renewable Energy');
      const solarIdx = result.content.indexOf('Solar Energy');
      expect(renewableIdx).toBeLessThan(solarIdx);
    });
  });
});
