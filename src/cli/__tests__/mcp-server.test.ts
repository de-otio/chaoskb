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
    chunk: vi.fn().mockReturnValue([]),
    embed: vi.fn().mockResolvedValue(new Float32Array(384)),
    embedChunks: vi.fn().mockResolvedValue([]),
    search: vi.fn().mockReturnValue([]),
  };

  const mockEncryption: IEncryptionService = {
    generateMasterKey: vi.fn(),
    deriveKeys: vi.fn(),
    encrypt: vi.fn().mockReturnValue({ envelope: {}, bytes: new Uint8Array() }),
    decrypt: vi.fn(),
    generateBlobId: vi.fn().mockReturnValue('b_test123'),
  };

  const mockKeys: DerivedKeySet = {
    contentKey: { buffer: Buffer.alloc(32), length: 32, isDisposed: false, dispose: vi.fn() },
    metadataKey: { buffer: Buffer.alloc(32), length: 32, isDisposed: false, dispose: vi.fn() },
    embeddingKey: { buffer: Buffer.alloc(32), length: 32, isDisposed: false, dispose: vi.fn() },
    commitKey: { buffer: Buffer.alloc(32), length: 32, isDisposed: false, dispose: vi.fn() },
  };

  return {
    db: mockDb,
    dbManager: mockDbManager,
    pipeline: mockPipeline,
    encryption: mockEncryption,
    keys: mockKeys,
  };
}

describe('MCP Server', () => {
  describe('Tool Definitions', () => {
    it('should define all 5 tools', () => {
      expect(TOOL_DEFINITIONS).toHaveLength(5);
    });

    it('should include kb_ingest tool with correct schema', () => {
      const tool = TOOL_DEFINITIONS.find((t) => t.name === 'kb_ingest');
      expect(tool).toBeDefined();
      expect(tool!.inputSchema.required).toContain('url');
      expect(tool!.inputSchema.properties).toHaveProperty('url');
      expect(tool!.inputSchema.properties).toHaveProperty('tags');
    });

    it('should include kb_query tool with correct schema', () => {
      const tool = TOOL_DEFINITIONS.find((t) => t.name === 'kb_query');
      expect(tool).toBeDefined();
      expect(tool!.inputSchema.required).toContain('query');
      expect(tool!.inputSchema.properties).toHaveProperty('query');
      expect(tool!.inputSchema.properties).toHaveProperty('limit');
    });

    it('should include kb_list tool with correct schema', () => {
      const tool = TOOL_DEFINITIONS.find((t) => t.name === 'kb_list');
      expect(tool).toBeDefined();
      expect(tool!.inputSchema.properties).toHaveProperty('limit');
      expect(tool!.inputSchema.properties).toHaveProperty('offset');
      expect(tool!.inputSchema.properties).toHaveProperty('tags');
    });

    it('should include kb_delete tool with correct schema', () => {
      const tool = TOOL_DEFINITIONS.find((t) => t.name === 'kb_delete');
      expect(tool).toBeDefined();
      expect(tool!.inputSchema.required).toContain('id');
    });

    it('should include kb_summary tool with correct schema', () => {
      const tool = TOOL_DEFINITIONS.find((t) => t.name === 'kb_summary');
      expect(tool).toBeDefined();
      expect(tool!.inputSchema.required).toContain('period');
    });

    it('should have descriptions for all tools', () => {
      for (const tool of TOOL_DEFINITIONS) {
        expect(tool.description).toBeTruthy();
        expect(typeof tool.description).toBe('string');
        expect(tool.description.length).toBeGreaterThan(10);
      }
    });
  });

  describe('Server Creation', () => {
    it('should create a server instance', () => {
      const deps = createMockDeps();
      const server = createMcpServer(deps);
      expect(server).toBeDefined();
    });
  });
});

export { createMockDeps };
