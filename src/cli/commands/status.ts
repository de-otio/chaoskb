import * as fs from 'node:fs';
import * as path from 'node:path';
import { loadConfig, CHAOSKB_DIR } from './setup.js';
import { detectAgents } from '../agent-registry/detector.js';

export interface StatusOptions {
  projectName?: string;
}

export async function statusCommand(options: StatusOptions): Promise<void> {
  const config = await loadConfig();

  console.log('');
  console.log('  ChaosKB Status');
  console.log('  ==============');
  console.log('');

  // Registered agents (show even before config exists)
  console.log('  Registered agents:');
  const agents = await detectAgents();
  const registeredAgents = agents.filter((a) => a.registered);
  if (registeredAgents.length === 0) {
    console.log('    (none — run `chaoskb-mcp register`)');
  } else {
    for (const agent of registeredAgents) {
      console.log(`    - ${agent.config.displayName}`);
    }
  }
  console.log('');

  if (!config) {
    console.log('  Knowledge base: not initialized yet');
    console.log('');
    if (registeredAgents.length > 0) {
      console.log('  Ready to use. Restart your agent, then try:');
      console.log('    "Save this to my KB: https://example.com/article"');
    } else {
      console.log('  Run `chaoskb-mcp register` to set up your agent.');
    }
    console.log('');
    return;
  }

  // Security tier
  console.log(`  Security tier:  ${config.securityTier}`);
  console.log('');

  // Storage usage
  console.log('  Storage:');
  const dbPath = path.join(CHAOSKB_DIR, 'local.db');
  if (fs.existsSync(dbPath)) {
    const stats = fs.statSync(dbPath);
    const sizeMb = (stats.size / 1024 / 1024).toFixed(2);
    console.log(`    Database: ${dbPath} (${sizeMb} MB)`);
    try {
      const { DatabaseManager } = await import('../../storage/database-manager.js');
      const dbManager = new DatabaseManager();
      const db = options.projectName
        ? dbManager.getProjectDb(options.projectName)
        : dbManager.getPersonalDb();
      const sourceCount = db.sources.count();
      console.log(`    Sources:  ${sourceCount}`);
      dbManager.closeAll();
    } catch {
      console.log('    Sources:  (unable to query)');
    }
  } else {
    console.log('    Database: not initialized');
  }
  console.log('');

  // Sync endpoint
  if (config.endpoint) {
    console.log(`  Sync endpoint:  ${config.endpoint}`);
  } else {
    console.log('  Sync endpoint:  not configured (local-only mode)');
  }
  console.log('');

  // Model
  const modelsDir = path.join(CHAOSKB_DIR, 'models');
  const modelFile = path.join(modelsDir, 'snowflake-arctic-embed-s.onnx');
  if (fs.existsSync(modelFile)) {
    const modelStats = fs.statSync(modelFile);
    const modelMb = (modelStats.size / 1024 / 1024).toFixed(1);
    console.log(`  Model: snowflake-arctic-embed-s@384 (${modelMb} MB)`);
    console.log(`  Model path: ${modelFile}`);
  } else {
    console.log('  Model: not downloaded (will download on first use)');
  }
  console.log('');

  // Project KBs
  console.log('  Project KBs:');
  if (config.projects.length === 0) {
    console.log('    (none)');
  } else {
    for (const project of config.projects) {
      const projectDbPath = path.join(CHAOSKB_DIR, `project-${project.name}.db`);
      let sizeInfo = '';
      if (fs.existsSync(projectDbPath)) {
        const pStats = fs.statSync(projectDbPath);
        sizeInfo = ` (${(pStats.size / 1024 / 1024).toFixed(2)} MB)`;
      }
      console.log(`    - ${project.name}${sizeInfo} (created ${project.createdAt})`);
    }
  }
  console.log('');
}
