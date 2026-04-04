import { describe, it, expect } from 'vitest';
import { parseGhAuthStatus } from '../github.js';

describe('parseGhAuthStatus', () => {
  it('should detect username from standard output', () => {
    const output = `github.com
  ✓ Logged in to github.com account rmyers (keyring)
  - Active account: true
  - Git operations protocol: https
  - Token: gho_****
  - Token scopes: 'gist', 'read:org', 'repo', 'workflow'`;

    const result = parseGhAuthStatus(output);
    expect(result.username).toBe('rmyers');
    expect(result.accounts).toEqual(['rmyers']);
  });

  it('should detect username from "as" format', () => {
    const output = `github.com
  ✓ Logged in to github.com as rmyers`;

    const result = parseGhAuthStatus(output);
    expect(result.username).toBe('rmyers');
    expect(result.accounts).toEqual(['rmyers']);
  });

  it('should detect multiple accounts', () => {
    const output = `github.com
  ✓ Logged in to github.com account personal-user (keyring)
  - Active account: true

  ✓ Logged in to github.com account work-user (keyring)
  - Active account: false`;

    const result = parseGhAuthStatus(output);
    expect(result.username).toBe('personal-user');
    expect(result.accounts).toEqual(['personal-user', 'work-user']);
  });

  it('should return null when not authenticated', () => {
    const output = `You are not logged in to any GitHub hosts. To log in, run: gh auth login`;

    const result = parseGhAuthStatus(output);
    expect(result.username).toBeNull();
    expect(result.accounts).toEqual([]);
  });

  it('should return null for empty output', () => {
    const result = parseGhAuthStatus('');
    expect(result.username).toBeNull();
    expect(result.accounts).toEqual([]);
  });

  it('should handle parentheses in account line', () => {
    const output = `github.com
  ✓ Logged in to github.com account myuser (oauth_token)`;

    const result = parseGhAuthStatus(output);
    expect(result.username).toBe('myuser');
  });
});
