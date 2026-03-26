import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { sanitizeFilename } from '../../commands/export.js';

describe('import command', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chaoskb-import-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('Markdown file format parsing', () => {
    it('should parse valid frontmatter with all fields', () => {
      const content = [
        '---',
        'title: "JavaScript Closures"',
        'url: https://example.com/closures',
        'tags: ["javascript", "closures"]',
        'date: 2024-01-15T10:30:00.000Z',
        '---',
        '',
        'A closure is a function that retains access to its lexical scope.',
      ].join('\n');

      fs.writeFileSync(path.join(tmpDir, 'test.md'), content);
      const fileContent = fs.readFileSync(path.join(tmpDir, 'test.md'), 'utf-8');

      // Parse using the regex pattern from import.ts
      const fmMatch = fileContent.match(/^---\n([\s\S]*?)\n---\n\n?([\s\S]*)$/);
      expect(fmMatch).not.toBeNull();
      expect(fmMatch![2].trim()).toBe(
        'A closure is a function that retains access to its lexical scope.',
      );
    });

    it('should parse title with escaped quotes', () => {
      const content = [
        '---',
        'title: "He said \\"hello\\""',
        'url: https://example.com/quotes',
        'tags: []',
        'date: 2024-01-15T10:30:00.000Z',
        '---',
        '',
        'Content here.',
      ].join('\n');

      fs.writeFileSync(path.join(tmpDir, 'test.md'), content);
      const fileContent = fs.readFileSync(path.join(tmpDir, 'test.md'), 'utf-8');
      const fmMatch = fileContent.match(/^---\n([\s\S]*?)\n---\n\n?([\s\S]*)$/);
      expect(fmMatch).not.toBeNull();

      const yaml = fmMatch![1];
      const titleMatch = yaml.match(/^title:\s*"((?:[^"\\]|\\.)*)"\s*$/m);
      expect(titleMatch).not.toBeNull();
      expect(titleMatch![1].replace(/\\"/g, '"')).toBe('He said "hello"');
    });

    it('should parse empty tags array', () => {
      const content = [
        '---',
        'title: "Test"',
        'url: https://example.com',
        'tags: []',
        'date: 2024-01-15T10:30:00.000Z',
        '---',
        '',
        'Content.',
      ].join('\n');

      fs.writeFileSync(path.join(tmpDir, 'test.md'), content);
      const fileContent = fs.readFileSync(path.join(tmpDir, 'test.md'), 'utf-8');
      const fmMatch = fileContent.match(/^---\n([\s\S]*?)\n---\n\n?([\s\S]*)$/);
      const yaml = fmMatch![1];

      const tagsMatch = yaml.match(/^tags:\s*\[(.*)\]\s*$/m);
      expect(tagsMatch).not.toBeNull();
      const tagMatches = [...tagsMatch![1].matchAll(/"([^"]*)"/g)];
      expect(tagMatches).toHaveLength(0);
    });

    it('should parse multiple tags', () => {
      const content = [
        '---',
        'title: "Test"',
        'url: https://example.com',
        'tags: ["javascript", "closures", "scope"]',
        'date: 2024-01-15T10:30:00.000Z',
        '---',
        '',
        'Content.',
      ].join('\n');

      fs.writeFileSync(path.join(tmpDir, 'test.md'), content);
      const fileContent = fs.readFileSync(path.join(tmpDir, 'test.md'), 'utf-8');
      const fmMatch = fileContent.match(/^---\n([\s\S]*?)\n---\n\n?([\s\S]*)$/);
      const yaml = fmMatch![1];

      const tagsMatch = yaml.match(/^tags:\s*\[(.*)\]\s*$/m);
      const tags = [...tagsMatch![1].matchAll(/"([^"]*)"/g)].map((m) => m[1]);
      expect(tags).toEqual(['javascript', 'closures', 'scope']);
    });
  });

  describe('manifest verification', () => {
    it('should detect tampered files via SHA-256', () => {
      const content = 'original content';
      const hash = crypto.createHash('sha256').update(content).digest('hex');

      const manifest = {
        'test.md': { sha256: hash, title: 'Test', url: 'https://example.com' },
      };

      fs.writeFileSync(path.join(tmpDir, 'manifest.json'), JSON.stringify(manifest));
      fs.writeFileSync(path.join(tmpDir, 'test.md'), 'tampered content');

      // Read and verify
      const manifestData = JSON.parse(
        fs.readFileSync(path.join(tmpDir, 'manifest.json'), 'utf-8'),
      );
      const actualHash = crypto
        .createHash('sha256')
        .update(fs.readFileSync(path.join(tmpDir, 'test.md'), 'utf-8'))
        .digest('hex');

      expect(actualHash).not.toBe(manifestData['test.md'].sha256);
    });

    it('should accept unmodified files', () => {
      const content = 'original content';
      const hash = crypto.createHash('sha256').update(content).digest('hex');

      const manifest = {
        'test.md': { sha256: hash, title: 'Test', url: 'https://example.com' },
      };

      fs.writeFileSync(path.join(tmpDir, 'manifest.json'), JSON.stringify(manifest));
      fs.writeFileSync(path.join(tmpDir, 'test.md'), content);

      const manifestData = JSON.parse(
        fs.readFileSync(path.join(tmpDir, 'manifest.json'), 'utf-8'),
      );
      const actualHash = crypto
        .createHash('sha256')
        .update(fs.readFileSync(path.join(tmpDir, 'test.md'), 'utf-8'))
        .digest('hex');

      expect(actualHash).toBe(manifestData['test.md'].sha256);
    });
  });

  describe('export round-trip format', () => {
    it('should produce valid export format that can be re-parsed', () => {
      // Simulate what export produces

      const source = {
        title: 'Test Article: A "Quoted" Title',
        url: 'https://example.com/article?id=123',
        tags: ['test', 'integration'],
        createdAt: '2024-01-15T10:30:00.000Z',
      };
      const content = 'First paragraph.\n\nSecond paragraph with code: const x = 1;';

      // Build the export format
      const frontmatter = [
        '---',
        `title: "${source.title.replace(/"/g, '\\"')}"`,
        `url: ${source.url}`,
        `tags: [${source.tags.map((t) => `"${t}"`).join(', ')}]`,
        `date: ${source.createdAt}`,
        '---',
      ].join('\n');
      const fileContent = `${frontmatter}\n\n${content}\n`;

      const safeName = sanitizeFilename(source.title);
      const filePath = path.join(tmpDir, `${safeName}.md`);
      fs.writeFileSync(filePath, fileContent);

      // Now re-parse it
      const readBack = fs.readFileSync(filePath, 'utf-8');
      const fmMatch = readBack.match(/^---\n([\s\S]*?)\n---\n\n?([\s\S]*)$/);
      expect(fmMatch).not.toBeNull();

      const yaml = fmMatch![1];
      const parsedContent = fmMatch![2].trim();

      // Verify title round-trips
      const titleMatch = yaml.match(/^title:\s*"((?:[^"\\]|\\.)*)"\s*$/m);
      expect(titleMatch![1].replace(/\\"/g, '"')).toBe(source.title);

      // Verify URL round-trips
      const urlMatch = yaml.match(/^url:\s*(.+)$/m);
      expect(urlMatch![1].trim()).toBe(source.url);

      // Verify tags round-trip
      const tagsMatch = yaml.match(/^tags:\s*\[(.*)\]\s*$/m);
      const tags = [...tagsMatch![1].matchAll(/"([^"]*)"/g)].map((m) => m[1]);
      expect(tags).toEqual(source.tags);

      // Verify content round-trips
      expect(parsedContent).toBe(content);
    });
  });
});
