import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fetchUrl, validateUrl, MAX_RESPONSE_BYTES } from '../fetch.js';

let server: Server;
let baseUrl: string;

function createHandler() {
  return (req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? '/';

    if (url === '/ok') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<html><body><p>Hello World</p></body></html>');
      return;
    }

    if (url === '/redirect') {
      res.writeHead(301, { Location: `${baseUrl}/ok` });
      res.end();
      return;
    }

    if (url === '/double-redirect') {
      res.writeHead(302, { Location: `${baseUrl}/redirect` });
      res.end();
      return;
    }

    if (url === '/not-found') {
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end('Not Found');
      return;
    }

    if (url === '/server-error') {
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end('Internal Server Error');
      return;
    }

    if (url === '/json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"key": "value"}');
      return;
    }

    if (url === '/pdf') {
      res.writeHead(200, { 'Content-Type': 'application/pdf' });
      res.end(Buffer.from([0x25, 0x50, 0x44, 0x46]));
      return;
    }

    if (url === '/slow') {
      // Intentionally don't respond for timeout testing
      setTimeout(() => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html><body>slow</body></html>');
      }, 5000);
      return;
    }

    if (url === '/xhtml') {
      res.writeHead(200, { 'Content-Type': 'application/xhtml+xml' });
      res.end('<html><body><p>XHTML content</p></body></html>');
      return;
    }

    if (url === '/check-ua') {
      const ua = req.headers['user-agent'] ?? '';
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<html><body>${ua}</body></html>`);
      return;
    }

    if (url === '/large') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      // Send 11 MB of content (exceeds 10 MB limit)
      const chunk = '<p>' + 'x'.repeat(1024 * 1024) + '</p>';
      for (let i = 0; i < 11; i++) {
        res.write(chunk);
      }
      res.end();
      return;
    }

    res.writeHead(404);
    res.end();
  };
}

beforeAll(async () => {
  server = createServer(createHandler());
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const addr = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
});

/** Config that skips SSRF check for localhost test server */
const LOCAL = { _skipSsrfCheck: true } as const;

describe('fetchUrl', () => {
  it('fetches HTML content successfully', async () => {
    const result = await fetchUrl(`${baseUrl}/ok`, LOCAL);
    expect(result.html).toContain('Hello World');
    expect(result.contentType).toContain('text/html');
    expect(result.finalUrl).toBe(`${baseUrl}/ok`);
  });

  it('follows redirects', async () => {
    const result = await fetchUrl(`${baseUrl}/redirect`, LOCAL);
    expect(result.html).toContain('Hello World');
    expect(result.finalUrl).toBe(`${baseUrl}/ok`);
  });

  it('follows multiple redirects', async () => {
    const result = await fetchUrl(`${baseUrl}/double-redirect`, LOCAL);
    expect(result.html).toContain('Hello World');
    expect(result.finalUrl).toBe(`${baseUrl}/ok`);
  });

  it('throws on 404', async () => {
    await expect(fetchUrl(`${baseUrl}/not-found`, LOCAL)).rejects.toThrow('HTTP 404 Client Error');
  });

  it('throws on 500', async () => {
    await expect(fetchUrl(`${baseUrl}/server-error`, LOCAL)).rejects.toThrow('HTTP 500 Server Error');
  });

  it('rejects non-HTML content (JSON)', async () => {
    await expect(fetchUrl(`${baseUrl}/json`, LOCAL)).rejects.toThrow('Non-HTML content type');
  });

  it('rejects non-HTML content (PDF)', async () => {
    await expect(fetchUrl(`${baseUrl}/pdf`, LOCAL)).rejects.toThrow('Non-HTML content type');
  });

  it('accepts XHTML content', async () => {
    const result = await fetchUrl(`${baseUrl}/xhtml`, LOCAL);
    expect(result.html).toContain('XHTML content');
  });

  it('times out on slow responses', async () => {
    await expect(
      fetchUrl(`${baseUrl}/slow`, { ...LOCAL, fetchTimeoutMs: 200 }),
    ).rejects.toThrow('timed out');
  });

  it('sends correct User-Agent header', async () => {
    const result = await fetchUrl(`${baseUrl}/check-ua`, LOCAL);
    expect(result.html).toContain('ChaosKB/0.1');
  });

  it('uses custom User-Agent when configured', async () => {
    const result = await fetchUrl(`${baseUrl}/check-ua`, {
      ...LOCAL,
      userAgent: 'CustomBot/2.0',
    });
    expect(result.html).toContain('CustomBot/2.0');
  });

  it('throws on DNS resolution failure', async () => {
    await expect(
      fetchUrl('http://this-domain-does-not-exist-xyz123.example.com/page'),
    ).rejects.toThrow();
  });

  it('blocks localhost by default (SSRF protection)', async () => {
    await expect(fetchUrl(`${baseUrl}/ok`)).rejects.toThrow(/private/);
  });

  it('rejects responses exceeding the size limit', async () => {
    await expect(fetchUrl(`${baseUrl}/large`, LOCAL)).rejects.toThrow(/exceeds.*MB limit/);
  });
});

describe('validateUrl (SSRF protection)', () => {
  it('rejects file:// URLs', async () => {
    await expect(validateUrl('file:///etc/passwd')).rejects.toThrow(/not allowed/);
  });

  it('rejects ftp:// URLs', async () => {
    await expect(validateUrl('ftp://example.com/file')).rejects.toThrow(/not allowed/);
  });

  it('rejects data: URLs', async () => {
    await expect(validateUrl('data:text/html,<h1>hi</h1>')).rejects.toThrow(/not allowed/);
  });

  it('rejects localhost IP', async () => {
    await expect(validateUrl('http://127.0.0.1/')).rejects.toThrow(/private/);
  });

  it('rejects 127.x.x.x range', async () => {
    await expect(validateUrl('http://127.0.0.2:8080/')).rejects.toThrow(/private/);
  });

  it('rejects 10.x.x.x private range', async () => {
    await expect(validateUrl('http://10.0.0.1/')).rejects.toThrow(/private/);
  });

  it('rejects 172.16.x.x private range', async () => {
    await expect(validateUrl('http://172.16.0.1/')).rejects.toThrow(/private/);
  });

  it('rejects 192.168.x.x private range', async () => {
    await expect(validateUrl('http://192.168.1.1/')).rejects.toThrow(/private/);
  });

  it('rejects AWS metadata endpoint IP', async () => {
    await expect(validateUrl('http://169.254.169.254/latest/meta-data/')).rejects.toThrow(/private/);
  });

  it('rejects IPv6 loopback', async () => {
    await expect(validateUrl('http://[::1]/')).rejects.toThrow(/private/);
  });

  it('rejects Google cloud metadata hostname', async () => {
    await expect(validateUrl('http://metadata.google.internal/')).rejects.toThrow(/cloud metadata/);
  });

  it('rejects 0.0.0.0', async () => {
    await expect(validateUrl('http://0.0.0.0/')).rejects.toThrow(/private/);
  });

  it('rejects IPv6 unspecified address', async () => {
    await expect(validateUrl('http://[::]/'))
      .rejects.toThrow(/private/);
  });

  it('rejects IPv6 ULA (fc00::/7)', async () => {
    await expect(validateUrl('http://[fc00::1]/')).rejects.toThrow(/private/);
    await expect(validateUrl('http://[fd12::1]/')).rejects.toThrow(/private/);
  });

  it('rejects IPv6 link-local (fe80::)', async () => {
    await expect(validateUrl('http://[fe80::1]/')).rejects.toThrow(/private/);
  });

  it('rejects IPv4-mapped IPv6 private address', async () => {
    await expect(validateUrl('http://[::ffff:127.0.0.1]/')).rejects.toThrow(/private/);
    await expect(validateUrl('http://[::ffff:10.0.0.1]/')).rejects.toThrow(/private/);
  });

  it('allows a public IPv6 address', async () => {
    // 2001:4860:4860::8888 is Google Public DNS
    await expect(validateUrl('http://[2001:4860:4860::8888]/')).resolves.toBeUndefined();
  });

  it('allows a public IPv4 address', async () => {
    // 8.8.8.8 is Google DNS — a known public IP
    await expect(validateUrl('http://8.8.8.8/')).resolves.toBeUndefined();
  });

  it('rejects hostname that resolves to localhost', async () => {
    // "localhost" resolves to 127.0.0.1 or ::1
    await expect(validateUrl('http://localhost/')).rejects.toThrow(/private/);
  });

  it('allows public URLs', async () => {
    // Should not throw for a well-known public domain
    await expect(validateUrl('https://example.com/')).resolves.toBeUndefined();
  });

  it('rejects invalid URLs', async () => {
    await expect(validateUrl('not-a-url')).rejects.toThrow(/Invalid URL/);
  });
});
