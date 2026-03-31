#!/usr/bin/env node

import { Command } from 'commander';
import { createRequire } from 'node:module';
import { startMcpServer } from './mcp-server.js';
import { setupCommand } from './commands/setup.js';
import { setupSyncCommand } from './commands/setup-sync.js';
import { unregisterCommand } from './commands/unregister.js';
import { statusCommand } from './commands/status.js';
import { exportCommand } from './commands/export.js';
import { importCommand } from './commands/import.js';
import { projectCommand } from './commands/project.js';
import {
  projectListAvailable,
  projectEnable,
  projectDisable,
  projectAccept,
  projectDecline,
} from './commands/projects.js';
import { uninstallCommand } from './commands/uninstall.js';
import { upgradeTierCommand } from './commands/config.js';
import { devicesAddCommand, devicesListCommand, devicesRemoveCommand } from './commands/devices.js';

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
    .command('help', { isDefault: false })
    .description('Show help and available commands')
    .action(() => {
      program.outputHelp();
    });

  program
    .command('setup')
    .description('Set up ChaosKB (auto-bootstraps if needed)')
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
    .command('unregister')
    .description('Remove ChaosKB from all agent configs')
    .action(async () => {
      await unregisterCommand();
    });

  const config = program
    .command('config')
    .description('Manage ChaosKB configuration');

  config
    .command('upgrade-tier <tier>')
    .description('Upgrade security tier to maximum (passphrase-protected)')
    .action(async (tier: string) => {
      await upgradeTierCommand(tier);
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

  program
    .command('uninstall')
    .description('Remove all ChaosKB data and agent registrations')
    .action(async () => {
      await uninstallCommand();
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

  project
    .command('list-available')
    .description('List shared projects available to you')
    .action(async () => {
      const { loadConfig } = await import('./commands/setup.js');
      const config = await loadConfig();
      if (!config) {
        console.error('ChaosKB is not set up. Run `chaoskb-mcp setup` first.');
        process.exit(1);
      }
      await projectListAvailable(config);
    });

  project
    .command('enable <name>')
    .description('Enable a shared project locally')
    .action(async (name: string) => {
      const { loadConfig } = await import('./commands/setup.js');
      const config = await loadConfig();
      if (!config) {
        console.error('ChaosKB is not set up. Run `chaoskb-mcp setup` first.');
        process.exit(1);
      }
      await projectEnable(config, name);
    });

  project
    .command('disable <name>')
    .description('Stop syncing a shared project and remove local data')
    .action(async (name: string) => {
      const { loadConfig } = await import('./commands/setup.js');
      const config = await loadConfig();
      if (!config) {
        console.error('ChaosKB is not set up. Run `chaoskb-mcp setup` first.');
        process.exit(1);
      }
      await projectDisable(config, name);
    });

  project
    .command('accept <name>')
    .description('Accept a project invite and enable it')
    .action(async (name: string) => {
      const { loadConfig } = await import('./commands/setup.js');
      const config = await loadConfig();
      if (!config) {
        console.error('ChaosKB is not set up. Run `chaoskb-mcp setup` first.');
        process.exit(1);
      }
      await projectAccept(config, name);
    });

  project
    .command('decline <name>')
    .description('Decline a project invite')
    .option('--block <sender>', 'Block the sender (e.g. @username)')
    .action(async (name: string, opts: { block?: string }) => {
      const { loadConfig } = await import('./commands/setup.js');
      const config = await loadConfig();
      if (!config) {
        console.error('ChaosKB is not set up. Run `chaoskb-mcp setup` first.');
        process.exit(1);
      }
      await projectDecline(config, name, opts.block);
    });

  const devices = program
    .command('devices')
    .description('Manage linked devices');

  devices
    .command('add')
    .description('Generate a link code to add a new device')
    .action(async () => {
      await devicesAddCommand();
    });

  devices
    .command('list')
    .description('List registered devices')
    .action(async () => {
      await devicesListCommand();
    });

  devices
    .command('remove <fingerprint>')
    .description('Remove a device by fingerprint')
    .action(async (fingerprint: string) => {
      await devicesRemoveCommand(fingerprint);
    });

  await program.parseAsync(process.argv);
}

main().catch((err: unknown) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
