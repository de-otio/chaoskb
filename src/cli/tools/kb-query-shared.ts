import type { McpDependencies } from '../mcp-server.js';
import { handleKbQuery } from './kb-query.js';
import type { KbQueryInput, KbQueryResultItem, KbQueryResult } from './kb-query.js';

export interface SharedSource {
  project: string;
  uploader: string;
  type: 'shared';
}

export interface KbQuerySharedResultItem extends KbQueryResultItem {
  source: SharedSource;
}

export interface KbQuerySharedResult {
  results: KbQuerySharedResultItem[];
  mode: string;
}

export interface KbQuerySharedInput extends KbQueryInput {
  project: string;
  uploader?: string;
}

/**
 * Wraps the existing kb-query logic but adds attribution metadata
 * (`source: { project, uploader, type: 'shared' }`) to each result.
 *
 * This makes content provenance visible to the agent when querying
 * shared project knowledge bases.
 */
export async function handleKbQueryShared(
  input: KbQuerySharedInput,
  deps: McpDependencies,
): Promise<KbQuerySharedResult> {
  const baseResult: KbQueryResult = await handleKbQuery(
    {
      query: input.query,
      limit: input.limit,
      mode: input.mode,
    },
    deps,
  );

  const results: KbQuerySharedResultItem[] = baseResult.results.map((item) => ({
    ...item,
    source: {
      project: input.project,
      uploader: input.uploader ?? 'unknown',
      type: 'shared' as const,
    },
  }));

  return {
    results,
    mode: baseResult.mode,
  };
}
