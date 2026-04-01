import * as fs from 'node:fs';
import * as readline from 'node:readline';
import { detectAgents } from '../agent-registry/detector.js';
import { removeAgentConfig } from '../agent-registry/config-merger.js';
import { CHAOSKB_DIR } from './setup.js';

function prompt(question: string): Promise<boolean> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y');
    });
  });
}

export async function uninstallCommand(options?: { dryRun?: boolean }): Promise<void> {
  const dryRun = options?.dryRun ?? false;
  console.log('');
  console.log('  ChaosKB Uninstall');
  console.log('  =================');
  console.log('');

  // 1. Check which agent configs will be modified
  const agents = await detectAgents();
  const registeredAgents = agents.filter((a) => a.registered);

  // 2. Check if local data directory exists
  const dataExists = fs.existsSync(CHAOSKB_DIR);

  if (registeredAgents.length === 0 && !dataExists) {
    console.log('  Nothing to uninstall — no agent registrations or local data found.');
    console.log('');
    return;
  }

  // 3. Show what will be removed
  console.log('  The following will be permanently removed:');
  console.log('');

  if (registeredAgents.length > 0) {
    console.log('  Agent registrations:');
    for (const agent of registeredAgents) {
      console.log(`    - ${agent.config.displayName}`);
      console.log(`      ${agent.configFilePath}`);
    }
    console.log('');
  }

  if (dataExists) {
    console.log(`  Local data directory:`);
    console.log(`    ${CHAOSKB_DIR}`);
    console.log('');
  }

  if (dryRun) {
    console.log('  [dry-run] No changes made.');
    console.log('');
    return;
  }

  const confirmed = await prompt('  This cannot be undone. Proceed? [y/N] ');
  if (!confirmed) {
    console.log('  Cancelled.');
    console.log('');
    return;
  }

  console.log('');

  // 4. Remove agent registrations
  for (const agent of registeredAgents) {
    try {
      await removeAgentConfig(agent.configFilePath);
      console.log(`  Removed from ${agent.config.displayName}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.log(`  Failed to remove from ${agent.config.displayName}: ${message}`);
    }
  }

  // 5. Delete local data directory
  if (dataExists) {
    try {
      fs.rmSync(CHAOSKB_DIR, { recursive: true, force: true });
      console.log(`  Deleted ${CHAOSKB_DIR}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.log(`  Failed to delete ${CHAOSKB_DIR}: ${message}`);
    }
  }

  console.log('');
  console.log('  Uninstall complete.');
  console.log('');
}
