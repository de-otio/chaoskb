import { createHash, sign as cryptoSign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { connect, type Socket } from 'node:net';

/**
 * Signs HTTP requests with an SSH private key for ChaosKB-SSH authentication.
 *
 * Uses Ed25519 keys. Attempts ssh-agent first if SSH_AUTH_SOCK is available,
 * then falls back to reading the private key file from disk.
 */
export class SSHSigner {
  private readonly keyPath: string;

  constructor(sshKeyPath?: string) {
    this.keyPath = sshKeyPath ?? join(homedir(), '.ssh', 'id_ed25519');
  }

  /**
   * Sign an HTTP request, returning the Authorization header value and timestamp.
   */
  async signRequest(
    method: string,
    path: string,
    body?: Uint8Array,
  ): Promise<{ authorization: string; timestamp: string }> {
    const timestamp = new Date().toISOString();
    const bodyHash = this.computeBodyHash(body);
    const canonical = this.buildCanonical(method, path, timestamp, bodyHash);

    const publicKeyRaw = await this.readPublicKey();
    const signature = await this.signCanonical(canonical);

    const base64PubKey = Buffer.from(publicKeyRaw).toString('base64');
    const base64Sig = signature.toString('base64');

    const authorization = `ChaosKB-SSH pubkey=${base64PubKey}, ts=${timestamp}, sig=${base64Sig}`;
    return { authorization, timestamp };
  }

  /**
   * Compute SHA-256 hex digest of body bytes. Empty string if no body.
   */
  computeBodyHash(body?: Uint8Array): string {
    if (!body || body.length === 0) {
      return '';
    }
    return createHash('sha256').update(body).digest('hex');
  }

  /**
   * Build the canonical string to be signed.
   */
  buildCanonical(method: string, path: string, timestamp: string, bodyHash: string): string {
    return `chaoskb-auth\n${method} ${path}\n${timestamp}\n${bodyHash}`;
  }

  /**
   * Read the SSH public key from the .pub file alongside the private key.
   * Returns the raw public key content as a UTF-8 string.
   */
  private async readPublicKey(): Promise<string> {
    const pubKeyPath = this.keyPath + '.pub';
    const content = await readFile(pubKeyPath, 'utf-8');
    return content.trim();
  }

  /**
   * Sign canonical data using the Ed25519 private key.
   *
   * Attempts ssh-agent first if SSH_AUTH_SOCK is set, falling back to
   * reading the key file from disk.
   */
  private async signCanonical(canonical: string): Promise<Buffer> {
    // Attempt ssh-agent if SSH_AUTH_SOCK is set
    if (process.env.SSH_AUTH_SOCK) {
      try {
        return await this.signWithAgent(canonical);
      } catch {
        // Fall through to file-based signing
      }
    }

    return this.signWithKeyFile(canonical);
  }

  /**
   * Sign using the SSH private key file on disk with Ed25519.
   */
  private async signWithKeyFile(canonical: string): Promise<Buffer> {
    const keyData = await readFile(this.keyPath, 'utf-8');
    const data = Buffer.from(canonical, 'utf-8');
    return cryptoSign(undefined, data, {
      key: keyData,
      format: 'pem',
    });
  }

  /**
   * Sign using ssh-agent via SSH_AUTH_SOCK.
   *
   * Implements the SSH agent protocol (draft-miller-ssh-agent):
   *   1. Connect to the Unix domain socket at SSH_AUTH_SOCK
   *   2. Send SSH_AGENTC_REQUEST_IDENTITIES to list available keys
   *   3. Find an Ed25519 key matching our public key
   *   4. Send SSH_AGENTC_SIGN_REQUEST with the data to sign
   *   5. Parse the SSH_AGENT_SIGN_RESPONSE to extract the signature
   */
  private async signWithAgent(canonical: string): Promise<Buffer> {
    const socketPath = process.env.SSH_AUTH_SOCK;
    if (!socketPath) {
      throw new Error('SSH_AUTH_SOCK not set');
    }

    const pubKeyContent = await this.readPublicKey();
    const pubKeyBlob = parseSSHPublicKey(pubKeyContent);

    const socket = await connectToAgent(socketPath);
    try {
      // Request the agent sign our data
      const data = Buffer.from(canonical, 'utf-8');
      const signatureBlob = await agentSign(socket, pubKeyBlob, data);

      // The signature blob from the agent is in SSH wire format:
      //   string  signature-format (e.g., "ssh-ed25519")
      //   string  signature-blob
      // We need the raw signature bytes for our authorization header.
      const sigData = parseSSHSignature(signatureBlob);
      return sigData;
    } finally {
      socket.destroy();
    }
  }
}

// --- SSH Agent Protocol Constants ---

/** SSH agent message types */
const SSH_AGENTC_SIGN_REQUEST = 13;
const SSH_AGENT_SIGN_RESPONSE = 14;
const SSH_AGENT_FAILURE = 5;

// --- SSH Agent Protocol Helpers ---

/**
 * Connect to the ssh-agent Unix domain socket.
 */
function connectToAgent(socketPath: string): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath, () => resolve(socket));
    socket.on('error', reject);
    socket.setTimeout(5000);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('ssh-agent connection timed out'));
    });
  });
}

/**
 * Send an SSH_AGENTC_SIGN_REQUEST and read the response.
 *
 * Wire format:
 *   uint32  length
 *   byte    SSH_AGENTC_SIGN_REQUEST (13)
 *   string  key_blob
 *   string  data
 *   uint32  flags (0 for default)
 */
function agentSign(socket: Socket, keyBlob: Buffer, data: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    // Build the message body
    const bodyParts: Buffer[] = [
      Buffer.from([SSH_AGENTC_SIGN_REQUEST]),
      sshString(keyBlob),
      sshString(data),
      uint32(0), // flags
    ];
    const body = Buffer.concat(bodyParts);

    // Prepend length header
    const message = Buffer.concat([uint32(body.length), body]);
    socket.write(message);

    // Read the response
    const chunks: Buffer[] = [];
    socket.on('data', (chunk: Buffer) => {
      chunks.push(chunk);

      // Check if we have enough data
      const response = Buffer.concat(chunks);
      if (response.length < 4) return; // Need length header

      const responseLen = response.readUInt32BE(0);
      if (response.length < 4 + responseLen) return; // Need full message

      const msgType = response[4];

      if (msgType === SSH_AGENT_FAILURE) {
        reject(new Error('ssh-agent refused the signing request (key may not be loaded)'));
        return;
      }

      if (msgType !== SSH_AGENT_SIGN_RESPONSE) {
        reject(new Error(`Unexpected ssh-agent response type: ${msgType}`));
        return;
      }

      // Parse: byte SSH_AGENT_SIGN_RESPONSE, string signature
      const sigOffset = 5; // 4 (length) + 1 (type)
      const sigLen = response.readUInt32BE(sigOffset);
      const signatureBlob = response.subarray(sigOffset + 4, sigOffset + 4 + sigLen);

      resolve(Buffer.from(signatureBlob));
    });

    socket.on('error', reject);
    socket.on('close', () => {
      reject(new Error('ssh-agent connection closed unexpectedly'));
    });
  });
}

/**
 * Parse an SSH public key line (e.g., "ssh-ed25519 AAAA... comment")
 * into the raw key blob (base64-decoded middle field).
 */
function parseSSHPublicKey(pubKeyLine: string): Buffer {
  const parts = pubKeyLine.trim().split(/\s+/);
  if (parts.length < 2) {
    throw new Error('Invalid SSH public key format');
  }
  return Buffer.from(parts[1], 'base64');
}

/**
 * Parse an SSH signature blob to extract the raw signature bytes.
 *
 * Wire format:
 *   string  format (e.g., "ssh-ed25519")
 *   string  signature
 */
function parseSSHSignature(blob: Buffer): Buffer {
  let offset = 0;

  // Skip format string
  const formatLen = blob.readUInt32BE(offset);
  offset += 4 + formatLen;

  // Read signature string
  const sigLen = blob.readUInt32BE(offset);
  offset += 4;

  return Buffer.from(blob.subarray(offset, offset + sigLen));
}

/**
 * Encode a buffer as an SSH string (uint32 length + bytes).
 */
function sshString(buf: Buffer): Buffer {
  return Buffer.concat([uint32(buf.length), buf]);
}

/**
 * Encode a number as a big-endian uint32.
 */
function uint32(n: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(n);
  return buf;
}
