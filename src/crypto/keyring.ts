import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { SecureBuffer } from './secure-buffer.js';
import type { IKeyringService, ISecureBuffer } from './types.js';

const execFileAsync = promisify(execFile);

/**
 * OS keyring integration via shell commands.
 * Uses execFile (not exec) to prevent shell injection.
 *
 * macOS:  security add-generic-password / find-generic-password / delete-generic-password
 * Linux:  secret-tool store / lookup / clear
 * Windows: cmdkey /add: / /list: / /delete:
 */
export class KeyringService implements IKeyringService {
  private readonly platform: NodeJS.Platform;

  constructor(platform?: NodeJS.Platform) {
    this.platform = platform ?? process.platform;
  }

  /**
   * Store a secret in the OS keyring.
   */
  async store(service: string, account: string, secret: ISecureBuffer): Promise<void> {
    const secretHex = secret.buffer.toString('hex');

    try {
      switch (this.platform) {
        case 'darwin':
          await this.storeMacOS(service, account, secretHex);
          break;
        case 'linux':
          await this.storeLinux(service, account, secretHex);
          break;
        case 'win32':
          await this.storeWindows(service, account, secretHex);
          break;
        default:
          throw new Error(`Unsupported platform: ${this.platform}`);
      }
    } finally {
      // We can't zero the hex string (JS strings are immutable),
      // but we at least don't hold onto it.
    }
  }

  /**
   * Retrieve a secret from the OS keyring.
   * Returns null if not found.
   */
  async retrieve(service: string, account: string): Promise<ISecureBuffer | null> {
    try {
      let secretHex: string;

      switch (this.platform) {
        case 'darwin':
          secretHex = await this.retrieveMacOS(service, account);
          break;
        case 'linux':
          secretHex = await this.retrieveLinux(service, account);
          break;
        case 'win32':
          secretHex = await this.retrieveWindows(service, account);
          break;
        default:
          throw new Error(`Unsupported platform: ${this.platform}`);
      }

      const bytes = Buffer.from(secretHex.trim(), 'hex');
      return SecureBuffer.from(bytes);
    } catch {
      return null;
    }
  }

  /**
   * Delete a secret from the OS keyring.
   * Returns true if deleted, false if not found.
   */
  async delete(service: string, account: string): Promise<boolean> {
    try {
      switch (this.platform) {
        case 'darwin':
          await this.deleteMacOS(service, account);
          break;
        case 'linux':
          await this.deleteLinux(service, account);
          break;
        case 'win32':
          await this.deleteWindows(service, account);
          break;
        default:
          throw new Error(`Unsupported platform: ${this.platform}`);
      }
      return true;
    } catch {
      return false;
    }
  }

  // --- macOS ---

  private async storeMacOS(service: string, account: string, secret: string): Promise<void> {
    // Delete existing entry first (update = delete + add)
    try {
      await execFileAsync('security', [
        'delete-generic-password',
        '-s', service,
        '-a', account,
      ]);
    } catch {
      // Ignore if not found
    }

    await execFileAsync('security', [
      'add-generic-password',
      '-s', service,
      '-a', account,
      '-w', secret,
      '-U', // update if exists
    ]);
  }

  private async retrieveMacOS(service: string, account: string): Promise<string> {
    const { stdout } = await execFileAsync('security', [
      'find-generic-password',
      '-s', service,
      '-a', account,
      '-w', // output password only
    ]);
    return stdout.trim();
  }

  private async deleteMacOS(service: string, account: string): Promise<void> {
    await execFileAsync('security', [
      'delete-generic-password',
      '-s', service,
      '-a', account,
    ]);
  }

  // --- Linux ---

  private async storeLinux(service: string, account: string, secret: string): Promise<void> {
    // secret-tool reads from stdin
    const child = execFileAsync('secret-tool', [
      'store',
      '--label', `${service}/${account}`,
      'service', service,
      'account', account,
    ]);

    // Write secret to stdin
    if (child.child.stdin) {
      child.child.stdin.write(secret);
      child.child.stdin.end();
    }

    await child;
  }

  private async retrieveLinux(service: string, account: string): Promise<string> {
    const { stdout } = await execFileAsync('secret-tool', [
      'lookup',
      'service', service,
      'account', account,
    ]);
    return stdout;
  }

  private async deleteLinux(service: string, account: string): Promise<void> {
    await execFileAsync('secret-tool', [
      'clear',
      'service', service,
      'account', account,
    ]);
  }

  // --- Windows ---

  private async storeWindows(service: string, account: string, secret: string): Promise<void> {
    const target = `${service}/${account}`;
    // Use PowerShell with .NET CredentialManager API (no external modules required)
    const script = `
      Add-Type -AssemblyName System.Runtime.InteropServices
      $cred = New-Object System.Management.Automation.PSCredential('${account.replace(/'/g, "''")}', (ConvertTo-SecureString '${secret.replace(/'/g, "''")}' -AsPlainText -Force))
      cmdkey /add:${target} /user:${account} /pass:${secret}
    `.trim();
    await execFileAsync('powershell', ['-NoProfile', '-Command', script]);
  }

  private async retrieveWindows(service: string, account: string): Promise<string> {
    const target = `${service}/${account}`;
    // Use PowerShell with native .NET Credential API (no external modules needed)
    const script = `
      Add-Type @"
        using System;
        using System.Runtime.InteropServices;
        public class CredentialHelper {
          [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
          public static extern bool CredReadW(string target, int type, int flags, out IntPtr credential);
          [DllImport("advapi32.dll")]
          public static extern void CredFree(IntPtr credential);
          [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
          public struct CREDENTIAL {
            public int Flags; public int Type;
            public string TargetName; public string Comment;
            public long LastWritten; public int CredentialBlobSize;
            public IntPtr CredentialBlob; public int Persist;
            public int AttributeCount; public IntPtr Attributes;
            public string TargetAlias; public string UserName;
          }
          public static string Read(string target) {
            IntPtr ptr;
            if (!CredReadW(target, 1, 0, out ptr)) return "";
            var cred = (CREDENTIAL)Marshal.PtrToStructure(ptr, typeof(CREDENTIAL));
            var secret = Marshal.PtrToStringUni(cred.CredentialBlob, cred.CredentialBlobSize / 2);
            CredFree(ptr);
            return secret;
          }
        }
"@
      [CredentialHelper]::Read('${target.replace(/'/g, "''")}')
    `.trim();

    const { stdout } = await execFileAsync('powershell', ['-NoProfile', '-Command', script]);
    const result = stdout.trim();

    if (!result) {
      throw new Error(`Credential not found: ${target}`);
    }

    return result;
  }

  private async deleteWindows(service: string, account: string): Promise<void> {
    const target = `${service}/${account}`;
    await execFileAsync('cmdkey', ['/delete:' + target]);
  }
}
