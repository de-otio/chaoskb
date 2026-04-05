import * as readline from 'node:readline';
import { detectAgents } from '../agent-registry/detector.js';
import {
  mergeAgentConfig,
  previewAgentConfig,
  removeAgentConfig,
  autoRegisterVSCodeWorkspace,
  MCP_SCRIPT_PATH,
} from '../agent-registry/config-merger.js';
import type { DetectedAgent } from '../agent-registry/types.js';

function prompt(question: string): Promise<boolean> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y');
    });
  });
}

function formatEntry(entry: { command: string; args: string[] }): string[] {
  return JSON.stringify({ chaoskb: entry }, null, 2)
    .split('\n')
    .map((line) => `    ${line}`);
}

function printDiff(
  before: { command: string; args: string[] } | undefined,
  after: { command: string; args: string[] },
): void {
  if (before) {
    for (const line of formatEntry(before)) {
      console.log(`  - ${line}`);
    }
  }
  for (const line of formatEntry(after)) {
    console.log(`  + ${line}`);
  }
}

export interface RegisterOptions {
  agentName?: string;
  projectName?: string;
}

export async function registerCommand(options: RegisterOptions): Promise<void> {
  console.log('');
  console.log('  ChaosKB Agent Registration');
  console.log('  ==========================');
  console.log('');

  // 1. Detect installed agents
  const agents = await detectAgents();

  if (agents.length === 0) {
    console.log('  No supported agents detected.');
    console.log('');
    console.log('  You can manually add ChaosKB to any MCP-compatible agent:');
    console.log('  {');
    console.log('    "mcpServers": {');
    console.log('      "chaoskb": {');
    console.log('        "command": "chaoskb-mcp",');
    console.log('        "args": []');
    console.log('      }');
    console.log('    }');
    console.log('  }');
    console.log('');
    return;
  }

  // 2. Filter to specific agent if requested
  let targetAgents: DetectedAgent[];
  if (options.agentName) {
    targetAgents = agents.filter(
      (a) =>
        a.config.name.toLowerCase() === options.agentName!.toLowerCase() ||
        a.config.displayName.toLowerCase() === options.agentName!.toLowerCase(),
    );
    if (targetAgents.length === 0) {
      console.log(`  Agent "${options.agentName}" not found.`);
      console.log('  Detected agents:');
      for (const a of agents) {
        const status = a.installed ? 'installed' : 'not installed';
        console.log(`    - ${a.config.displayName} (${status})`);
      }
      console.log('');
      return;
    }
  } else {
    targetAgents = agents.filter((a) => a.installed);
  }

  if (targetAgents.length === 0) {
    console.log('  No installed agents found to register with.');
    console.log('');
    return;
  }

  // 3. Register with each target agent
  const registered: string[] = [];
  const failed: string[] = [];

  for (const agent of targetAgents) {
    try {
      const args: string[] = [];
      if (options.projectName) {
        args.push('--project', options.projectName);
      }

      const preview = previewAgentConfig(agent.configFilePath, args);
      const action = preview.isNew ? 'Add to' : 'Update';

      console.log(`  ${action} ${agent.config.displayName} config:`);
      console.log(`    ${preview.configFilePath}`);
      console.log('');
      printDiff(preview.before, preview.after);
      console.log('');

      const confirmed = await prompt('  Proceed? [y/N] ');
      if (!confirmed) {
        console.log('  Skipped.');
        console.log('');
        continue;
      }

      await mergeAgentConfig(agent.configFilePath, args);
      registered.push(agent.config.displayName);
      console.log(`  Done.`);
      console.log('');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      failed.push(`${agent.config.displayName}: ${message}`);
      console.log(`  Failed to register with ${agent.config.displayName}: ${message}`);
      console.log('');
    }
  }

  console.log('');
  if (registered.length > 0) {
    console.log(`  Successfully registered with ${registered.length} agent(s):`);
    for (const name of registered) {
      console.log(`    - ${name}`);
    }
  }
  if (failed.length > 0) {
    console.log(`  Failed to register with ${failed.length} agent(s):`);
    for (const msg of failed) {
      console.log(`    - ${msg}`);
    }
  }
  if (options.projectName) {
    console.log(`  Project: ${options.projectName}`);
  }

  // If running inside VS Code, also register in the workspace .mcp.json
  const workspaceRoot = autoRegisterVSCodeWorkspace();
  if (workspaceRoot) {
    console.log(`  Registered in workspace .mcp.json (${workspaceRoot})`);
    registered.push('VS Code workspace');
  }

  // Print manual config snippet for project-level MCP config files
  const manualArgs: string[] = [MCP_SCRIPT_PATH];
  if (options.projectName) {
    manualArgs.push('--project', options.projectName);
  }
  const manualEntry = {
    mcpServers: {
      chaoskb: {
        command: process.execPath,
        args: manualArgs,
      },
    },
  };
  console.log('  To add manually to a project MCP config file:');
  console.log('');
  const lines = JSON.stringify(manualEntry, null, 2).split('\n');
  for (const line of lines) {
    console.log(`  ${line}`);
  }
  console.log('');
}

export { removeAgentConfig };
