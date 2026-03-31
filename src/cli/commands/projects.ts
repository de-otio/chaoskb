import * as fs from 'node:fs';
import * as path from 'node:path';
import { loadConfig, saveConfig, CHAOSKB_DIR } from './setup.js';
import type { ChaosKBConfig } from '../mcp-server.js';
import { SequenceCounter } from '../../sync/sequence.js';

const sequence = new SequenceCounter();

/** Convert signRequest result to fetch-compatible headers. */
function toHeaders(result: { authorization: string; timestamp: string; sequence: number; publicKey: string }, extra?: Record<string, string>): Record<string, string> {
  return {
    Authorization: result.authorization,
    'X-ChaosKB-Timestamp': result.timestamp,
    'X-ChaosKB-Sequence': String(result.sequence),
    'X-ChaosKB-PublicKey': result.publicKey,
    ...extra,
  };
}

export interface SharedProjectMeta {
  name: string;
  role: string;
  owner: string;
  itemCount: number;
}

export interface ProjectKeyResponse {
  encryptedKey: string;
  algorithm: string;
}

/**
 * List shared projects available to the current user.
 * Calls GET /v1/projects/available (server returns metadata only).
 */
export async function projectListAvailable(config: ChaosKBConfig): Promise<SharedProjectMeta[]> {
  if (!config.endpoint) {
    console.error('Sync is not configured. Run `chaoskb-mcp setup-sync` first.');
    process.exit(1);
  }

  const { SSHSigner } = await import('../../sync/ssh-signer.js');
  const signer = new SSHSigner(config.sshKeyPath!);

  const url = `${config.endpoint}/v1/projects/available`;
  const signed = await signer.signRequest('GET', '/v1/projects/available', sequence.next());

  const res = await fetch(url, { method: 'GET', headers: toHeaders(signed) });

  if (!res.ok) {
    const body = await res.text();
    console.error(`Server error (${res.status}): ${body}`);
    process.exit(1);
  }

  const data = (await res.json()) as { projects: SharedProjectMeta[] };
  const projects = data.projects;

  // Display as table
  console.log('');
  console.log('  Available Shared Projects');
  console.log('  =========================');
  console.log('');

  if (projects.length === 0) {
    console.log('  No shared projects available.');
    console.log('');
    return projects;
  }

  const nameWidth = Math.max(4, ...projects.map((p) => p.name.length));
  const roleWidth = Math.max(4, ...projects.map((p) => p.role.length));
  const ownerWidth = Math.max(5, ...projects.map((p) => p.owner.length));

  const header = `  ${'NAME'.padEnd(nameWidth)}  ${'ROLE'.padEnd(roleWidth)}  ${'OWNER'.padEnd(ownerWidth)}  ITEMS`;
  console.log(header);
  console.log(`  ${'-'.repeat(header.length - 2)}`);

  for (const p of projects) {
    console.log(
      `  ${p.name.padEnd(nameWidth)}  ${p.role.padEnd(roleWidth)}  ${p.owner.padEnd(ownerWidth)}  ${p.itemCount}`,
    );
  }
  console.log('');

  return projects;
}

/**
 * Enable a shared project locally: download key, create directory, add to config.
 */
export async function projectEnable(config: ChaosKBConfig, projectName: string): Promise<void> {
  if (!config.endpoint) {
    console.error('Sync is not configured. Run `chaoskb-mcp setup-sync` first.');
    process.exit(1);
  }

  // Check if already enabled
  const existing = config.projects.find((p) => p.name === projectName);
  if (existing) {
    console.log(`Project "${projectName}" is already enabled.`);
    return;
  }

  const { SSHSigner } = await import('../../sync/ssh-signer.js');
  const signer = new SSHSigner(config.sshKeyPath!);

  // Download encrypted project key
  const keyUrl = `${config.endpoint}/v1/projects/${encodeURIComponent(projectName)}/key`;
  const keyHeaders = await signer.signRequest('GET', `/v1/projects/${encodeURIComponent(projectName)}/key`, sequence.next());

  const keyRes = await fetch(keyUrl, { method: 'GET', headers: toHeaders(keyHeaders) });

  if (!keyRes.ok) {
    const body = await keyRes.text();
    console.error(`Failed to download project key (${keyRes.status}): ${body}`);
    process.exit(1);
  }

  const keyData = (await keyRes.json()) as ProjectKeyResponse;

  // Create project directory
  const projectDir = path.join(CHAOSKB_DIR, 'projects', projectName);
  fs.mkdirSync(projectDir, { recursive: true, mode: 0o700 });

  // Store project key in keyring
  // Stub: in production, we'd decrypt the project key using invite crypto
  // and store the decrypted key. For now, store the encrypted key directly.
  const { KeyringService } = await import('../../crypto/keyring.js');
  const keyring = new KeyringService();
  await keyring.store(`chaoskb/project-${projectName}`, 'key', keyData.encryptedKey);

  // Add to config
  config.projects.push({ name: projectName, createdAt: new Date().toISOString() });
  await saveConfig(config);

  // Sync project data
  console.log(`Syncing ${projectName}...`);

  // Stub: actual sync would pull blobs and decrypt them.
  // For now, count items from the project directory.
  const itemCount = 0; // Placeholder — real sync happens in Phase 2+
  console.log(`Syncing ${projectName}... done (${itemCount} items)`);
}

/**
 * Disable a shared project: remove directory, keyring entry, and config entry.
 */
export async function projectDisable(config: ChaosKBConfig, projectName: string): Promise<void> {
  const index = config.projects.findIndex((p) => p.name === projectName);
  if (index === -1) {
    console.error(`Project "${projectName}" is not enabled.`);
    process.exit(1);
  }

  // Remove project directory
  const projectDir = path.join(CHAOSKB_DIR, 'projects', projectName);
  try {
    fs.rmSync(projectDir, { recursive: true, force: true });
  } catch {
    // Directory may not exist; that's fine
  }

  // Remove project key from keyring
  try {
    const { KeyringService } = await import('../../crypto/keyring.js');
    const keyring = new KeyringService();
    await keyring.delete(`chaoskb/project-${projectName}`, 'key');
  } catch {
    // Key may not exist in keyring; that's fine
  }

  // Remove from config
  config.projects.splice(index, 1);
  await saveConfig(config);

  console.log(`Stopped syncing ${projectName}. Local data removed.`);
}

/**
 * Accept a project invite and enable the project.
 */
export async function projectAccept(config: ChaosKBConfig, projectName: string): Promise<void> {
  if (!config.endpoint) {
    console.error('Sync is not configured. Run `chaoskb-mcp setup-sync` first.');
    process.exit(1);
  }

  const { SSHSigner } = await import('../../sync/ssh-signer.js');
  const signer = new SSHSigner(config.sshKeyPath!);

  // Accept the invite via server
  const acceptUrl = `${config.endpoint}/v1/invites/${encodeURIComponent(projectName)}/accept`;
  const acceptHeaders = await signer.signRequest('POST', `/v1/invites/${encodeURIComponent(projectName)}/accept`, sequence.next());

  const acceptRes = await fetch(acceptUrl, {
    method: 'POST',
    headers: toHeaders(acceptHeaders, { 'Content-Type': 'application/json' }),
    body: JSON.stringify({}),
  });

  if (!acceptRes.ok) {
    const body = await acceptRes.text();
    console.error(`Failed to accept invite (${acceptRes.status}): ${body}`);
    process.exit(1);
  }

  console.log(`Invite for "${projectName}" accepted.`);

  // Now enable the project locally
  await projectEnable(config, projectName);
}

/**
 * Decline a project invite, optionally blocking the sender.
 */
export async function projectDecline(
  config: ChaosKBConfig,
  projectName: string,
  block?: string,
): Promise<void> {
  if (!config.endpoint) {
    console.error('Sync is not configured. Run `chaoskb-mcp setup-sync` first.');
    process.exit(1);
  }

  const { SSHSigner } = await import('../../sync/ssh-signer.js');
  const signer = new SSHSigner(config.sshKeyPath!);

  const declineUrl = `${config.endpoint}/v1/invites/${encodeURIComponent(projectName)}/decline`;
  const declineHeaders = await signer.signRequest('POST', `/v1/invites/${encodeURIComponent(projectName)}/decline`, sequence.next());

  const declineRes = await fetch(declineUrl, {
    method: 'POST',
    headers: toHeaders(declineHeaders, { 'Content-Type': 'application/json' }),
    body: JSON.stringify({ block: block ?? null }),
  });

  if (!declineRes.ok) {
    const body = await declineRes.text();
    console.error(`Failed to decline invite (${declineRes.status}): ${body}`);
    process.exit(1);
  }

  const blockMsg = block ? ` (blocked ${block})` : '';
  console.log(`Invite for "${projectName}" declined${blockMsg}.`);
}
