# Troubleshooting

## Agent doesn't see ChaosKB tools

**Symptom:** Your chat agent doesn't recognize `kb_ingest`, `kb_query`, etc.

**Fix:**
1. Check registration: `chaoskb-mcp register`
2. Restart your chat agent (it reads MCP config on startup)
3. Verify the binary is on your PATH: `which chaoskb-mcp`
4. Check status: `chaoskb-mcp status`

If auto-registration doesn't work for your agent, add the config manually. See [Chat Agent Setup](chat-agent-setup.md#manual-registration).

## Model download fails or is slow

**Symptom:** First run hangs or errors during the ~134 MB embedding model download.

**Fix:**
- Check your internet connection
- The download destination is `~/.chaoskb/models/`. Ensure you have disk space.
- If the download was interrupted, delete `~/.chaoskb/models/` and restart. It will re-download.
- If the hash verification fails after download, the file may be corrupted. Delete and retry.

## "Sync failed" or sync not working

**Symptom:** Articles aren't appearing on other devices, or you see sync error messages.

**Fix:**
1. Check your server configuration: `chaoskb-mcp status`
2. Test the connection: the status command shows whether the server is reachable
3. If your SSH key was rotated, register the new key: `chaoskb-mcp setup rotate-key --new-key ~/.ssh/id_ed25519_new.pub`
4. If sync has been paused for a long time (>25 days), a full resync will run automatically on next connection

Sync is best-effort. If the server is unreachable, articles save locally and sync when the connection returns. No data is lost.

## "Unable to unlock" or wrong key errors

**Symptom:** ChaosKB reports that it can't decrypt your data.

This means the encryption key in your device's keystore doesn't match your data. This can happen after:
- A factory reset
- An OS upgrade that invalidated the keystore
- A device migration that didn't transfer keychain items

**Fix by tier:**
- **Standard:** Ensure your SSH private key is available (via ssh-agent or `~/.ssh/id_ed25519`). The wrapped master key is downloaded from the server and unwrapped locally.
- **Enhanced:** Enter your 24-word recovery key when prompted.
- **Maximum:** Enter your passphrase when prompted.

If recovery succeeds, the key is re-stored in your keystore for next time.

## Storage full (sync stopped)

**Symptom:** "Synced storage full. New articles are saved locally only."

Your synced storage quota is full. New articles still save and search locally — only server backup is paused.

**Fix:**
- Free space: **Settings > Manage Library**. Sort by largest or oldest to find articles to delete. See [Managing Your Library](managing-your-library.md#bulk-cleanup).
- Upgrade your plan for more synced storage.
- Or do nothing — local-only mode works fine.

## Article ingest fails

**Symptom:** "Could not fetch", "Extraction failed", "URL blocked", or "possible-prompt-injection" when saving a URL.

**Common causes:**
- The URL is on a known malicious-site blocklist ("URL blocked" error)
- The fetched page matched prompt-injection patterns — content like "ignore all previous instructions" is rejected by default to keep adversarial text out of your KB ("possible-prompt-injection" error)
- The URL is behind a paywall or login wall (ChaosKB fetches as an anonymous visitor)
- The site blocks automated requests
- The content is an unsupported format (images, video, etc.)
- Network connectivity issue

**Fix:** Try the URL in your browser. If it loads, the site may be blocking non-browser requests. There is no workaround for paywalled content. URLs on the malicious-site blocklist are hard-blocked.

If a legitimate page is being rejected for "possible-prompt-injection" (e.g., an article that quotes an injection example for educational purposes), you can downgrade the check to a warning with:

```bash
chaoskb-mcp config safety --injection-policy warn
```

Run `chaoskb-mcp config safety --help` for the full list of safety options (URL threat-intel feeds, strict mode, secrets policy, etc.).

For local files, use the `filePath` parameter instead of `url`. ChaosKB supports PDF, DOCX, PPTX, HTML, TXT, and MD files.

## Data looks corrupted

**Symptom:** Articles have missing content, garbled text, or decryption errors on specific items.

This is rare. Possible causes: interrupted upload, bit flip in transit, server storage error.

**Fix:**
1. Check the specific article: try deleting and re-saving the URL
2. If multiple articles are affected, try a full resync: delete `~/.chaoskb/local.db` and restart (this re-downloads and re-decrypts everything from the server)
3. If the problem persists, export your data and report the issue

## Need more help?

Report issues at https://github.com/de-otio/chaoskb/issues
