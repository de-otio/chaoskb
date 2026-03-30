import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fs from 'node:fs';

vi.mock('node:fs');

describe('loadEmbeddedRegistry', () => {
  it('loads without throwing (registry.json is bundled)', async () => {
    // This test must NOT mock the registry module — that's the whole point.
    // If registry.json is missing from the package, this will throw
    // "Cannot find module './registry.json'" at import time.
    const { loadEmbeddedRegistry } = await import('../../agent-registry/index.js');
    expect(() => loadEmbeddedRegistry()).not.toThrow();
  });

  it('returns a valid registry shape', async () => {
    const { loadEmbeddedRegistry } = await import('../../agent-registry/index.js');
    const registry = loadEmbeddedRegistry();

    expect(typeof registry.version).toBe('number');
    expect(typeof registry.updatedAt).toBe('string');
    expect(Array.isArray(registry.agents)).toBe(true);
    expect(registry.agents.length).toBeGreaterThan(0);
  });

  it('each agent has required fields', async () => {
    const { loadEmbeddedRegistry } = await import('../../agent-registry/index.js');
    const { agents } = loadEmbeddedRegistry();

    for (const agent of agents) {
      expect(typeof agent.name, `agent.name for ${agent.name}`).toBe('string');
      expect(typeof agent.displayName, `agent.displayName for ${agent.name}`).toBe('string');
      expect(Array.isArray(agent.platforms), `agent.platforms for ${agent.name}`).toBe(true);
      expect(typeof agent.installPaths, `agent.installPaths for ${agent.name}`).toBe('object');
      expect(typeof agent.configPath, `agent.configPath for ${agent.name}`).toBe('object');
      expect(agent.configFormat, `agent.configFormat for ${agent.name}`).toBe('json');
      expect(typeof agent.supportsProjectConfig, `agent.supportsProjectConfig for ${agent.name}`).toBe('boolean');
    }
  });
});

describe('loadCachedRegistry', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns null when cache file does not exist', async () => {
    vi.mocked(fs.readFileSync).mockImplementation(() => {
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    });

    const { loadCachedRegistry } = await import('../../agent-registry/index.js');
    expect(loadCachedRegistry()).toBeNull();
  });

  it('returns parsed registry when cache file exists', async () => {
    const cached = { version: 2, updatedAt: new Date().toISOString(), agents: [] };
    vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(cached));

    const { loadCachedRegistry } = await import('../../agent-registry/index.js');
    expect(loadCachedRegistry()).toEqual(cached);
  });
});

describe('isRegistryStale', () => {
  it('returns true for registry older than 90 days', async () => {
    const { isRegistryStale } = await import('../../agent-registry/index.js');
    const old = { version: 1, updatedAt: '2020-01-01T00:00:00Z', agents: [] };
    expect(isRegistryStale(old)).toBe(true);
  });

  it('returns false for recently updated registry', async () => {
    const { isRegistryStale } = await import('../../agent-registry/index.js');
    const fresh = { version: 1, updatedAt: new Date().toISOString(), agents: [] };
    expect(isRegistryStale(fresh)).toBe(false);
  });
});
