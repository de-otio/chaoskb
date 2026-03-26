import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { IDatabase, IDatabaseManager } from '../storage/types.js';
import type { IContentPipeline } from '../pipeline/types.js';
import type { IEncryptionService, DerivedKeySet } from '../crypto/types.js';
import { handleKbIngest } from './tools/kb-ingest.js';
import { handleKbQuery } from './tools/kb-query.js';
import { handleKbList } from './tools/kb-list.js';
import { handleKbDelete } from './tools/kb-delete.js';
import { handleKbSummary } from './tools/kb-summary.js';

export interface McpServerOptions {
  projectName?: string;
}

export interface McpDependencies {
  db: IDatabase;
  dbManager: IDatabaseManager;
  pipeline: IContentPipeline;
  encryption: IEncryptionService;
  keys: DerivedKeySet;
}

const TOOL_DEFINITIONS = [
  {
    name: 'kb_ingest',
    description:
      'Ingest a URL into the knowledge base. Fetches content, extracts text, chunks, embeds, encrypts, and stores locally.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        url: { type: 'string', description: 'URL to ingest' },
        tags: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional tags to assign to the source',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'kb_query',
    description:
      'Search the knowledge base. Supports semantic (embedding) search, keyword (FTS5) search, or hybrid (both combined).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        query: { type: 'string', description: 'Search query' },
        limit: {
          type: 'number',
          description: 'Maximum number of results to return (default: 10)',
        },
        mode: {
          type: 'string',
          enum: ['semantic', 'keyword', 'hybrid'],
          description: 'Search mode: "semantic" (default) for meaning-based, "keyword" for exact text match, "hybrid" for combined ranking',
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'kb_list',
    description:
      'List saved sources in the knowledge base with metadata.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        limit: {
          type: 'number',
          description: 'Maximum number of sources to return (default: 20)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default: 0)',
        },
        tags: {
          type: 'array',
          items: { type: 'string' },
          description: 'Filter by tags',
        },
      },
    },
  },
  {
    name: 'kb_delete',
    description:
      'Soft-delete a source and its chunks from the knowledge base.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: { type: 'string', description: 'Source ID to delete' },
      },
      required: ['id'],
    },
  },
  {
    name: 'kb_summary',
    description:
      'Get a summary of articles added during a time period. Returns structured data for the agent to summarize.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        period: {
          type: 'string',
          description:
            'Time period: "week", "month", "year", or custom range "YYYY-MM-DD:YYYY-MM-DD"',
        },
      },
      required: ['period'],
    },
  },
];

export function createMcpServer(deps: McpDependencies): Server {
  const server = new Server(
    { name: 'chaoskb', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFINITIONS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      switch (name) {
        case 'kb_ingest': {
          const result = await handleKbIngest(
            {
              url: (args as Record<string, unknown>).url as string,
              tags: (args as Record<string, unknown>).tags as string[] | undefined,
            },
            deps,
          );
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }
        case 'kb_query': {
          const result = await handleKbQuery(
            {
              query: (args as Record<string, unknown>).query as string,
              limit: (args as Record<string, unknown>).limit as number | undefined,
              mode: (args as Record<string, unknown>).mode as 'semantic' | 'keyword' | 'hybrid' | undefined,
            },
            deps,
          );
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }
        case 'kb_list': {
          const result = await handleKbList(
            {
              limit: (args as Record<string, unknown>).limit as number | undefined,
              offset: (args as Record<string, unknown>).offset as number | undefined,
              tags: (args as Record<string, unknown>).tags as string[] | undefined,
            },
            deps,
          );
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }
        case 'kb_delete': {
          const result = await handleKbDelete(
            {
              id: (args as Record<string, unknown>).id as string,
            },
            deps,
          );
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }
        case 'kb_summary': {
          const result = await handleKbSummary(
            {
              period: (args as Record<string, unknown>).period as string,
            },
            deps,
          );
          return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
        }
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: 'text', text: `Error: ${message}` }],
        isError: true,
      };
    }
  });

  return server;
}

export async function startMcpServer(options: McpServerOptions): Promise<void> {
  // In production, dependencies are initialized here.
  // For now, we set up the server structure and connect transport.
  // Actual initialization requires loading config, opening DB, etc.

  const { loadConfig } = await import('./commands/setup.js');
  const config = await loadConfig();

  if (!config) {
    console.error(
      'ChaosKB is not set up. Run `chaoskb-mcp setup` first.',
    );
    process.exit(1);
  }

  // These would be real implementations in production.
  // The module structure supports dependency injection for testability.
  // For the MCP server startup, we dynamically load the real implementations.

  // Placeholder: in a real build, these come from the actual modules
  const deps: McpDependencies = await initializeDependencies(options, config);
  const server = createMcpServer(deps);
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

async function initializeDependencies(
  options: McpServerOptions,
  _config: ChaosKBConfig,
): Promise<McpDependencies> {
  // Dynamic imports to keep startup fast when running in CLI mode
  const { KeyringService } = await import('../crypto/keyring.js');
  const { EncryptionService } = await import('../crypto/encryption-service.js');
  const { DatabaseManager } = await import('../storage/database-manager.js');
  const { ModelManager } = await import('../pipeline/model-manager.js');
  const { Embedder } = await import('../pipeline/embedder.js');
  const { ContentPipeline } = await import('../pipeline/content-pipeline.js');

  // 1. Retrieve master key from OS keyring
  const keyring = new KeyringService();
  const masterKey = await keyring.retrieve('chaoskb', 'master-key');
  if (!masterKey) {
    throw new Error(
      'Master key not found in OS keyring. Run `chaoskb-mcp setup` first.',
    );
  }

  // 2. Derive key set from master key
  const encryption = new EncryptionService();
  const keys = encryption.deriveKeys(masterKey);

  // 3. Initialize database
  const dbManager = new DatabaseManager();
  const db = options.projectName
    ? dbManager.getProjectDb(options.projectName)
    : dbManager.getPersonalDb();

  // 4. Load embedding index from database
  db.embeddingIndex.load();

  // 5. Ensure ONNX model is available and create content pipeline
  const modelManager = new ModelManager();
  const modelPath = await modelManager.ensureModel((downloaded, total) => {
    if (total > 0) {
      // Write progress to stderr (stdout is reserved for MCP JSON-RPC)
      process.stderr.write(
        `\rDownloading embedding model: ${Math.round((downloaded / total) * 100)}%`,
      );
    }
  });
  // Clear the progress line
  process.stderr.write('\r\x1b[K');

  const embedder = new Embedder(modelPath);
  const pipeline = new ContentPipeline(
    {
      maxChunkTokens: 500,
      overlapTokens: 50,
      fetchTimeoutMs: 30000,
      maxRedirects: 5,
      userAgent: 'ChaosKB/0.1',
    },
    embedder,
  );

  return { db, dbManager, pipeline, encryption, keys };
}

/** ChaosKB configuration file shape */
export interface ChaosKBConfig {
  endpoint?: string;
  sshKeyPath?: string;
  securityTier: string;
  projects: Array<{ name: string; createdAt: string }>;
}

export { TOOL_DEFINITIONS };
