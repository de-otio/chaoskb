import { createSyncClient } from './sync-client.js';

export interface RotateKeyInput {
  newKeyPath?: string;
}

/**
 * MCP tool: rotate_key
 *
 * Initiates Phase 1 of two-phase key rotation. Re-wraps the master key
 * with a new SSH key and registers it with the server.
 */
export async function handleRotateKey(input: RotateKeyInput): Promise<{
  status: string;
  message: string;
  newKeyPath?: string;
}> {
  // Delegate to the CLI command logic which handles the full rotation flow
  const { rotateKeyCommand } = await import('../commands/rotate-key.js');

  // Capture output by temporarily redirecting console
  const messages: string[] = [];
  const origLog = console.log;
  const origError = console.error;
  let exitCode = 0;
  const origExit = process.exitCode;

  console.log = (...args: unknown[]) => messages.push(args.join(' '));
  console.error = (...args: unknown[]) => messages.push(args.join(' '));

  try {
    await rotateKeyCommand(input.newKeyPath, { dryRun: false });
    exitCode = process.exitCode ?? 0;
  } finally {
    console.log = origLog;
    console.error = origError;
    process.exitCode = origExit;
  }

  if (exitCode !== 0) {
    throw new Error(messages.join('\n'));
  }

  return {
    status: 'rotation_started',
    message: messages.join('\n') || 'Key rotation Phase 1 complete. Other devices will pick up the new key on next sync.',
    newKeyPath: input.newKeyPath,
  };
}
