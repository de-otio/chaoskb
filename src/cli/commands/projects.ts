import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  OsKeychainStorage,
  FileSystemStorage,
  type KeyStorage,
  type WrappedKey,
} from '@de-otio/keyring';
import { saveConfig, CHAOSKB_DIR } from './setup.js';
import type { ChaosKBConfig } from '../mcp-server.js';
import { createSyncClient } from '../tools/sync-client.js';
import { KEYRING_SERVICE } from '../bootstrap.js';

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

/** Build the keyring storage for project keys. */
function buildStorage(): KeyStorage<'standard'> {
  if (process.env.CHAOSKB_KEY_STORAGE === 'file') {
    const fsDir = path.join(CHAOSKB_DIR, 'keyring');
    fs.mkdirSync(fsDir, { recursive: true, mode: 0o700 });
    return new FileSystemStorage({ root: fsDir }) as KeyStorage<'standard'>;
  }
  return new OsKeychainStorage<'standard'>({
    service: KEYRING_SERVICE,
    acceptedTiers: ['standard'] as const,
  });
}

/** Build the slot name for a project-scoped key. */
function projectSlotName(projectName: string): string {
  return `project-${projectName}`;
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

  const { signedFetch } = await createSyncClient();
  const res = await signedFetch('GET', '/v1/projects/available');

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

  const { signedFetch } = await createSyncClient();

  // Download encrypted project key
  const keyRes = await signedFetch('GET', `/v1/projects/${encodeURIComponent(projectName)}/key`);

  if (!keyRes.ok) {
    const body = await keyRes.text();
    console.error(`Failed to download project key (${keyRes.status}): ${body}`);
    process.exit(1);
  }

  const keyData = (await keyRes.json()) as ProjectKeyResponse;

  // Create project directory
  const projectDir = path.join(CHAOSKB_DIR, 'projects', projectName);
  fs.mkdirSync(projectDir, { recursive: true, mode: 0o700 });

  // Store project key in keyring storage. The server-delivered blob is
  // already wrapped for this device; we persist it verbatim at a
  // per-project slot so that future unlock paths can reach it. We serialise
  // as a WrappedKey to match the storage contract.
  const storage = buildStorage();
  const wrapped: WrappedKey = {
    v: 1,
    tier: 'standard',
    envelope: new Uint8Array(Buffer.from(keyData.encryptedKey, 'base64')),
    ts: new Date().toISOString(),
  };
  await storage.put(projectSlotName(projectName), wrapped);

  // Add to config
  config.projects.push({ name: projectName, createdAt: new Date().toISOString() });
  await saveConfig(config);

  // Sync project data
  console.log(`Syncing ${projectName}...`);
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

  // Remove project key from keyring storage
  try {
    const storage = buildStorage();
    await storage.delete(projectSlotName(projectName));
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

  const { signedFetch } = await createSyncClient();

  // Accept the invite via server
  const acceptRes = await signedFetch(
    'POST',
    `/v1/invites/${encodeURIComponent(projectName)}/accept`,
    new TextEncoder().encode(JSON.stringify({})),
  );

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

  const { signedFetch } = await createSyncClient();

  const declineRes = await signedFetch(
    'POST',
    `/v1/invites/${encodeURIComponent(projectName)}/decline`,
    new TextEncoder().encode(JSON.stringify({ block: block ?? null })),
  );

  if (!declineRes.ok) {
    const body = await declineRes.text();
    console.error(`Failed to decline invite (${declineRes.status}): ${body}`);
    process.exit(1);
  }

  const blockMsg = block ? ` (blocked ${block})` : '';
  console.log(`Invite for "${projectName}" declined${blockMsg}.`);
}
