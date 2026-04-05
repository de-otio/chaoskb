#!/usr/bin/env node

/**
 * npm postinstall: auto-register ChaosKB with detected MCP-compatible agents.
 *
 * Runs silently — writes to stderr only on success so the user knows it worked.
 * Never fails the install (all errors are swallowed).
 */

import { detectAgents } from './agent-registry/detector.js';
import { mergeAgentConfig, autoRegisterVSCodeWorkspace } from './agent-registry/config-merger.js';

async function main(): Promise<void> {
  const agents = await detectAgents();
  const installed = agents.filter((a) => a.installed);

  const registered: string[] = [];

  // Register with detected agents (global config files)
  for (const agent of installed) {
    try {
      if (agent.registered) {
        registered.push(`${agent.config.displayName} (already registered)`);
        continue;
      }

      await mergeAgentConfig(agent.configFilePath);
      registered.push(agent.config.displayName);
    } catch {
      // Never fail the install — registration is best-effort
    }
  }

  // If running inside VS Code, also register in the workspace .mcp.json
  // (the VS Code extension reads MCP servers from .mcp.json, not global settings)
  try {
    const workspaceRoot = autoRegisterVSCodeWorkspace();
    if (workspaceRoot) {
      registered.push('VS Code workspace (.mcp.json)');
    }
  } catch {
    // Best-effort
  }

  if (registered.length > 0) {
    process.stderr.write(
      `\n  ChaosKB registered with: ${registered.join(', ')}\n` +
      `  Restart your agent to activate.\n\n`,
    );
  }
}

main().catch(() => {
  // Silently ignore — postinstall must never fail
});
