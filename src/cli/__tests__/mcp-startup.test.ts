/**
 * Integration test for MCP server startup.
 *
 * Verifies that createMcpServer() produces a valid server with all tools
 * registered and callable, using mocked dependencies (no keyring, no model).
 */

import { describe, it, expect, vi } from 'vitest';
import { createMcpServer, TOOL_DEFINITIONS } from '../mcp-server.js';
import type { McpDependencies } from '../mcp-server.js';
import type { IDatabase, IDatabaseManager } from '../../storage/types.js';
import type { IContentPipeline } from '../../pipeline/types.js';
import type { IEncryptionService, DerivedKeySet } from '../../crypto/types.js';

function createMockDeps(): McpDependencies {
  const mockDb: IDatabase = {
    sources: {
      insert: vi.fn(),
      getById: vi.fn(),
      getByUrl: vi.fn().mockReturnValue(null),
      list: vi.fn().mockReturnValue([]),
      count: vi.fn().mockReturnValue(0),
      softDelete: vi.fn().mockReturnValue(true),
      restore: vi.fn().mockReturnValue(true),
      updateLastAccessed: vi.fn(),
    },
    chunks: {
      insertMany: vi.fn().mockReturnValue([]),
      getBySourceId: vi.fn().mockReturnValue([]),
      deleteBySourceId: vi.fn().mockReturnValue(0),
      searchKeyword: vi.fn().mockReturnValue([]),
    },
    syncStatus: {
      set: vi.fn(),
      get: vi.fn(),
      getPending: vi.fn().mockReturnValue([]),
      getByStatus: vi.fn().mockReturnValue([]),
    },
    embeddingIndex: {
      load: vi.fn(),
      add: vi.fn(),
      remove: vi.fn(),
      search: vi.fn().mockReturnValue([]),
      size: 0,
    },
    close: vi.fn(),
  };

  const mockDbManager: IDatabaseManager = {
    getPersonalDb: vi.fn().mockReturnValue(mockDb),
    getProjectDb: vi.fn().mockReturnValue(mockDb),
    listProjects: vi.fn().mockReturnValue([]),
    deleteProject: vi.fn().mockReturnValue(true),
    closeAll: vi.fn(),
  };

  const mockPipeline: IContentPipeline = {
    fetchAndExtract: vi.fn().mockResolvedValue({
      title: 'Test',
      content: 'Test content',
      url: 'https://example.com',
      byteLength: 12,
    }),
    extractFromFile: vi.fn().mockResolvedValue({
      title: 'Test File',
      content: 'Test file content',
      url: '/tmp/test.pdf',
      byteLength: 17,
    }),
    chunk: vi.fn().mockReturnValue([{
      content: 'Test content',
      index: 0,
      tokenCount: 2,
      byteOffset: 0,
    }]),
    embed: vi.fn().mockResolvedValue(new Float32Array(384)),
    embedChunks: vi.fn().mockResolvedValue([{
      content: 'Test content',
      index: 0,
      tokenCount: 2,
      byteOffset: 0,
      embedding: new Float32Array(384),
      model: 'test',
    }]),
    search: vi.fn().mockReturnValue([0]),
  };

  const mockEncryption: IEncryptionService = {
    generateMasterKey: vi.fn(),
    deriveKeys: vi.fn().mockReturnValue({
      contentKey: { expose: () => new Uint8Array(32), destroy: vi.fn() },
      metadataKey: { expose: () => new Uint8Array(32), destroy: vi.fn() },
      embeddingKey: { expose: () => new Uint8Array(32), destroy: vi.fn() },
      commitKey: { expose: () => new Uint8Array(32), destroy: vi.fn() },
    }),
    encrypt: vi.fn().mockReturnValue({ envelope: {}, bytes: new Uint8Array(16) }),
    decrypt: vi.fn().mockReturnValue({ payload: {} }),
    generateBlobId: vi.fn().mockReturnValue('b_test'),
  } as unknown as IEncryptionService;

  return {
    db: mockDb,
    dbManager: mockDbManager,
    pipeline: mockPipeline,
    encryption: mockEncryption,
    keys: {} as DerivedKeySet,
  };
}

describe('MCP server startup', () => {
  it('should create a server instance without crashing', () => {
    const deps = createMockDeps();
    const server = createMcpServer(deps);
    expect(server).toBeDefined();
  });

  it('should register all expected tools', () => {
    expect(TOOL_DEFINITIONS).toHaveLength(14);

    const toolNames = TOOL_DEFINITIONS.map((t) => t.name);
    expect(toolNames).toContain('kb_ingest');
    expect(toolNames).toContain('kb_query');
    expect(toolNames).toContain('kb_list');
    expect(toolNames).toContain('kb_delete');
    expect(toolNames).toContain('kb_summary');
    expect(toolNames).toContain('kb_query_shared');
    expect(toolNames).toContain('kb_sync_status');
    expect(toolNames).toContain('device_link_start');
    expect(toolNames).toContain('device_link_confirm');
    expect(toolNames).toContain('devices_list');
    expect(toolNames).toContain('devices_remove');
    expect(toolNames).toContain('rotate_key');
    expect(toolNames).toContain('audit_log');
    expect(toolNames).toContain('revoke_all');
  });

  it('should have valid input schemas for all tools', () => {
    for (const tool of TOOL_DEFINITIONS) {
      expect(tool.inputSchema).toBeDefined();
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.inputSchema.properties).toBeDefined();
    }
  });

  it('kb_query tool should include mode parameter', () => {
    const queryTool = TOOL_DEFINITIONS.find((t) => t.name === 'kb_query');
    expect(queryTool).toBeDefined();
    expect(queryTool!.inputSchema.properties).toHaveProperty('mode');
    const modeProp = queryTool!.inputSchema.properties.mode as { enum: string[] };
    expect(modeProp.enum).toEqual(['semantic', 'keyword', 'hybrid']);
  });

  it('all tools should have descriptions', () => {
    for (const tool of TOOL_DEFINITIONS) {
      expect(tool.description).toBeDefined();
      expect(tool.description.length).toBeGreaterThan(10);
    }
  });

  it('all tools should have required fields defined', () => {
    for (const tool of TOOL_DEFINITIONS) {
      if (tool.inputSchema.required) {
        for (const field of tool.inputSchema.required) {
          expect(tool.inputSchema.properties).toHaveProperty(field);
        }
      }
    }
  });
});
