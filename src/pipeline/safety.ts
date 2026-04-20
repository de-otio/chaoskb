/**
 * Lazy-initialised safety checker for the content pipeline.
 *
 * Wraps @de-otio/agent-safety-pack and layers chaoskb-specific policy
 * dials on top: whether matched prompt-injection and secrets content
 * blocks ingestion or just emits a warning.
 *
 * Call `initSafetyChecker(config)` once at MCP startup after loading
 * `~/.chaoskb/config.json`. Subsequent calls re-build the checker with
 * the new config (useful for tests and for hot-reloading the
 * `chaoskb-mcp config safety` command output).
 *
 * If `getSafetyChecker()` / policy accessors are called before init,
 * defaults are used (same as pre-configurable behaviour).
 */

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createSafetyChecker,
  type SafetyChecker,
  type SafetyCheckerConfig,
} from '@de-otio/agent-safety-pack';

export type ContentPolicy = 'block' | 'warn' | 'allow';

/**
 * chaoskb-level safety configuration. Fields forwarded to the pack's
 * `createSafetyChecker()` plus two chaoskb-internal policy dials for
 * how extracted content that trips a pattern match is handled.
 */
export interface ChaosKbSafetyConfig {
  /** Promote `'ask'` decisions to `'deny'` (pack `strict` mode). Default false. */
  strict?: boolean;
  /** Enable local threat-feed lookups (pack default true). */
  localFeeds?: boolean;
  /** Remote threat-intel APIs, all off unless explicitly enabled. */
  remoteApis?: {
    urlhaus?: boolean;
    googleSafeBrowsing?: string;
    spamhausDbl?: boolean;
  };
  /** Milliseconds per remote API call. Pack default 5000. */
  remoteTimeoutMs?: number;
  /** How to treat prompt-injection matches. Default 'block'. */
  injectionPolicy?: ContentPolicy;
  /** How to treat secrets/credential matches. Default 'warn'. */
  secretsPolicy?: ContentPolicy;
}

// Resolve patterns/ relative to the installed agent-safety-pack main entry.
const _indexPath = fileURLToPath(import.meta.resolve('@de-otio/agent-safety-pack'));
const _patternsDir = resolve(dirname(dirname(_indexPath)), 'patterns');

const DEFAULT_INJECTION_POLICY: ContentPolicy = 'block';
const DEFAULT_SECRETS_POLICY: ContentPolicy = 'warn';

let _checker: SafetyChecker | null = null;
let _injectionPolicy: ContentPolicy = DEFAULT_INJECTION_POLICY;
let _secretsPolicy: ContentPolicy = DEFAULT_SECRETS_POLICY;

function buildPackConfig(c?: ChaosKbSafetyConfig): SafetyCheckerConfig {
  const packConfig: SafetyCheckerConfig = {
    patternsDir: _patternsDir,
    localFeeds: c?.localFeeds ?? true,
  };
  if (c?.strict !== undefined) packConfig.strict = c.strict;
  if (c?.remoteApis) packConfig.remoteApis = c.remoteApis;
  if (c?.remoteTimeoutMs !== undefined) {
    packConfig.timeouts = { remoteApi: c.remoteTimeoutMs };
  }
  return packConfig;
}

/**
 * Build (or rebuild) the safety checker with the given chaoskb config.
 * Pass `undefined` or omit to restore defaults.
 */
export function initSafetyChecker(config?: ChaosKbSafetyConfig): void {
  _checker = createSafetyChecker(buildPackConfig(config));
  _injectionPolicy = config?.injectionPolicy ?? DEFAULT_INJECTION_POLICY;
  _secretsPolicy = config?.secretsPolicy ?? DEFAULT_SECRETS_POLICY;
}

export function getSafetyChecker(): SafetyChecker {
  if (!_checker) initSafetyChecker();
  return _checker!;
}

export function getInjectionPolicy(): ContentPolicy {
  return _injectionPolicy;
}

export function getSecretsPolicy(): ContentPolicy {
  return _secretsPolicy;
}
