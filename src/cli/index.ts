#!/usr/bin/env node

import { Command } from 'commander';
import { createRequire } from 'node:module';
import { startMcpServer } from './mcp-server.js';
import { setupCommand } from './commands/setup.js';
import { setupSyncCommand } from './commands/setup-sync.js';
import { registerCommand } from './commands/register.js';
import { unregisterCommand } from './commands/unregister.js';
import { statusCommand } from './commands/status.js';
import { exportCommand } from './commands/export.js';
import { importCommand } from './commands/import.js';
import { projectCommand } from './commands/project.js';

const require = createRequire(import.meta.url);
const pkg = require('../../package.json') as { version: string };

async function main(): Promise<void> {
  // If stdin is a pipe (not TTY), start MCP server mode
  if (!process.stdin.isTTY) {
    const projectFlag = process.argv.find((arg, i) =>
      arg === '--project' && i + 1 < process.argv.length
    );
    const projectName = projectFlag
      ? process.argv[process.argv.indexOf('--project') + 1]
      : undefined;
    await startMcpServer({ projectName });
    return;
  }

  // TTY mode: parse CLI commands with commander
  const program = new Command();

  program
    .name('chaoskb-mcp')
    .description('ChaosKB - E2E encrypted personal knowledge base')
    .version(pkg.version)
    .option('--project <name>', 'scope operations to a project KB');

  program
    .command('setup')
    .description('Interactive first-time setup')
    .action(async () => {
      await setupCommand();
    });

  program
    .command('setup-sync')
    .description('Configure sync with server')
    .action(async () => {
      await setupSyncCommand();
    });

  program
    .command('register')
    .description('Register ChaosKB with installed agents')
    .option('--agent <name>', 'register with specific agent')
    .option('--project <name>', 'register for a project KB')
    .action(async (opts: { agent?: string; project?: string }) => {
      const globalProject = program.opts().project as string | undefined;
      await registerCommand({
        agentName: opts.agent,
        projectName: opts.project ?? globalProject,
      });
    });

  program
    .command('unregister')
    .description('Remove ChaosKB from all agent configs')
    .action(async () => {
      await unregisterCommand();
    });

  program
    .command('status')
    .description('Show current configuration and stats')
    .action(async () => {
      const globalProject = program.opts().project as string | undefined;
      await statusCommand({ projectName: globalProject });
    });

  program
    .command('export')
    .description('Export KB data')
    .option('--format <format>', 'export format: encrypted or plaintext', 'encrypted')
    .option('--output <path>', 'output directory', '.')
    .action(async (opts: { format: string; output: string }) => {
      const globalProject = program.opts().project as string | undefined;
      await exportCommand({
        format: opts.format as 'encrypted' | 'plaintext',
        outputPath: opts.output,
        projectName: globalProject,
      });
    });

  program
    .command('import <path>')
    .description('Import a previously exported KB')
    .option('--overwrite', 'overwrite existing sources with same URL')
    .action(async (inputPath: string, opts: { overwrite?: boolean }) => {
      const globalProject = program.opts().project as string | undefined;
      await importCommand({
        inputPath,
        overwrite: opts.overwrite,
        projectName: globalProject,
      });
    });

  const project = program
    .command('project')
    .description('Manage project knowledge bases');

  project
    .command('create <name>')
    .description('Create a project KB')
    .action(async (name: string) => {
      await projectCommand({ action: 'create', name });
    });

  project
    .command('list')
    .description('List project KBs')
    .action(async () => {
      await projectCommand({ action: 'list' });
    });

  project
    .command('delete <name>')
    .description('Delete a project KB')
    .action(async (name: string) => {
      await projectCommand({ action: 'delete', name });
    });

  await program.parseAsync(process.argv);
}

main().catch((err: unknown) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
