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
import { upgradeTierCommand, safetyCommand } from './commands/config.js';
import { rotateKeyCommand } from './commands/rotate-key.js';
import { devicesAddCommand, devicesListCommand, devicesRemoveCommand } from './commands/devices.js';
import { notificationsListCommand, notificationsDismissCommand } from './commands/notifications.js';
import { kbCreateCommand, kbListCommand, kbDeleteCommand } from './commands/kb.js';

const require = createRequire(import.meta.url);
const pkg = require('../../package.json') as { version: string };

/** Global options that consume the next argument as a value. */
const OPTIONS_WITH_VALUE = new Set(['--project']);

/**
 * Determine whether to start MCP server mode based on TTY status and arguments.
 * MCP mode is used when stdin is piped (non-TTY) and no explicit CLI command or
 * info flag (--version, --help) is present.
 */
export function shouldStartMcpServer(isTTY: boolean, args: string[]): boolean {
  const hasFlag = args.some(arg => arg === '--version' || arg === '-V' || arg === '--help' || arg === '-h');
  let hasCommand = false;
  for (let i = 0; i < args.length; i++) {
    if (OPTIONS_WITH_VALUE.has(args[i])) {
      i++; // skip the value that follows
    } else if (!args[i].startsWith('-')) {
      hasCommand = true;
      break;
    }
  }
  return !isTTY && !hasCommand && !hasFlag;
}

async function main(): Promise<void> {
  // If stdin is a pipe (not TTY) AND no explicit CLI command is given,
  // start MCP server mode. This allows CLI commands to work in non-TTY
  // environments (CI, piped shells, agent terminals).
  const args = process.argv.slice(2);
  if (shouldStartMcpServer(!!process.stdin.isTTY, args)) {
    const projectFlag = process.argv.find((arg, i) =>
      arg === '--project' && i + 1 < process.argv.length
    );
    const projectName = projectFlag
      ? process.argv[process.argv.indexOf('--project') + 1]
      : undefined;
    await startMcpServer({ projectName });
    return;
  }

  // CLI mode: parse commands with commander
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
    .option('--github <username>', 'link to a GitHub account for automatic device linking')
    .option('--github-auto', 'auto-detect GitHub account and match SSH keys')
    .action(async (opts: { github?: string; githubAuto?: boolean }) => {
      await setupSyncCommand({ github: opts.github, githubAuto: opts.githubAuto });
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
    .option('--dry-run', 'show what would happen without making changes')
    .action(async (tier: string, opts: { dryRun?: boolean }) => {
      await upgradeTierCommand(tier, { dryRun: opts.dryRun });
    });

  config
    .command('rotate-key')
    .description('Rotate the SSH key used for sync')
    .option('--new-key <path>', 'path to the new SSH private key')
    .option('--dry-run', 'show what would happen without making changes')
    .action(async (opts: { newKey?: string; dryRun?: boolean }) => {
      await rotateKeyCommand(opts.newKey, { dryRun: opts.dryRun });
    });

  config
    .command('safety')
    .description('Show or update the safety-checker configuration')
    .option('--show', 'print the current configuration and exit')
    .option('--strict', 'promote ambiguous (ask) safety decisions to deny')
    .option('--no-strict', 'disable strict mode')
    .option('--urlhaus', 'enable URLhaus URL threat-intel lookups (no API key required)')
    .option('--no-urlhaus', 'disable URLhaus lookups')
    .option('--gsb-key <key>', 'Google Safe Browsing API key (enables GSB lookups)')
    .option('--clear-gsb-key', 'remove the stored Google Safe Browsing API key')
    .option('--spamhaus-dbl', 'enable Spamhaus DBL DNS-based URL lookups')
    .option('--no-spamhaus-dbl', 'disable Spamhaus DBL lookups')
    .option('--remote-timeout-ms <ms>', 'timeout for remote API calls (default 5000)')
    .option('--injection-policy <policy>', 'prompt-injection handling: block (default) | warn | allow')
    .option('--secrets-policy <policy>', 'secrets handling: block | warn (default) | allow')
    .option('--reset', 'reset the safety configuration to defaults')
    .action(async (opts) => {
      await safetyCommand(opts);
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
    .option('--dry-run', 'show what would be removed without making changes')
    .action(async (opts: { dryRun?: boolean }) => {
      await uninstallCommand({ dryRun: opts.dryRun });
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

  const notifications = program
    .command('notifications')
    .description('View and dismiss sync notifications');

  notifications
    .command('list')
    .description('Show unacknowledged notifications')
    .action(async () => {
      await notificationsListCommand();
    });

  notifications
    .command('dismiss [id]')
    .description('Dismiss a notification (or all if no ID given)')
    .action(async (id?: string) => {
      await notificationsDismissCommand(id);
    });

  const kb = program
    .command('kb')
    .description('Manage named knowledge bases');

  kb
    .command('create <name>')
    .description('Create a named KB with its own SSH key and sync identity')
    .option('--key <path>', 'path to the SSH private key for this KB')
    .option('--github <username>', 'link to a GitHub account')
    .action(async (name: string, opts: { key?: string; github?: string }) => {
      await kbCreateCommand(name, opts);
    });

  kb
    .command('list')
    .description('List all named KBs')
    .action(async () => {
      await kbListCommand();
    });

  kb
    .command('delete <name>')
    .description('Delete a named KB and its local data')
    .action(async (name: string) => {
      await kbDeleteCommand(name);
    });

  await program.parseAsync(process.argv);
}

main().catch((err: unknown) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
