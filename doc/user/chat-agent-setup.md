# Chat Agent Setup

ChaosKB runs as an MCP server that any compatible chat agent can use. When you install ChaosKB with `npm install -g @de-otio/chaoskb-client`, it automatically registers with all detected agents (Claude Code, Cursor, VS Code, Claude Desktop).

## After install

1. **Restart your agent** (close and reopen Claude Code, Cursor, etc.)
2. **Verify it works** — ask your agent: *"What ChaosKB tools are available?"*
3. **Try it** — tell your agent: *"Save this article to my KB: https://example.com"*

If ChaosKB wasn't auto-detected during install, register manually:

```bash
chaoskb-mcp register                    # detect and register with all installed agents
chaoskb-mcp register --agent cursor     # register with a specific agent
```

Registration is interactive. For each detected agent, it shows exactly what it will write to the config file and asks for confirmation before making any changes:

```
  Add to Claude Code config:
    /Users/you/.claude/settings.json

  + {
  +   "chaoskb": {
  +     "command": "/usr/local/bin/node",
  +     "args": ["/usr/local/lib/node_modules/@de-otio/chaoskb-client/dist/cli/index.js"]
  +   }
  + }

  Proceed? [y/N]
```

If an agent is already registered and you re-run `register`, it shows a diff of what would change. Press `y` to confirm or `n` to skip that agent.

At the end, the command also prints the exact config snippet to paste manually if needed.

## Supported agents

| Agent | Config file (macOS) |
|-------|---------------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude/settings.json` |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| VS Code (Copilot) | `.vscode/mcp.json` or VS Code settings |
| Continue.dev | `~/.continue/config.json` |

Config paths vary by platform. Run `chaoskb-mcp register` to have the paths detected automatically.

## Manual registration

Run `chaoskb-mcp register` and copy the snippet printed at the end — it contains the exact absolute paths for your installation. Paste it into your agent's MCP config file.

The snippet looks like:

```json
{
  "mcpServers": {
    "chaoskb": {
      "command": "/usr/local/bin/node",
      "args": ["/usr/local/lib/node_modules/@de-otio/chaoskb-client/dist/cli/index.js"]
    }
  }
}
```

The exact paths will match your system. Using absolute paths avoids issues with `PATH` differences between your shell and the agent process.

If you've configured server sync, you can optionally include the endpoint in an `env` block:

```json
{
  "mcpServers": {
    "chaoskb": {
      "command": "/usr/local/bin/node",
      "args": ["/usr/local/lib/node_modules/@de-otio/chaoskb-client/dist/cli/index.js"],
      "env": {
        "CHAOSKB_ENDPOINT": "https://your-endpoint.lambda-url.us-east-1.on.aws"
      }
    }
  }
}
```

Authentication uses your SSH key via ssh-agent (Ed25519 primary, RSA fallback). No API key or credentials are stored in config files.

## How it works

ChaosKB is not a background service. Your chat agent spawns `chaoskb-mcp` as a child process when it starts and the process exits when the agent quits. No login items, no daemons, no background resource usage.

When the agent starts ChaosKB:
1. Loads your local database and embedding index
2. Syncs with the server (if configured)
3. Reports its tools as available
4. Waits for tool calls from the agent

Startup takes 1-3 seconds.

## Verifying it works

After restarting your agent, ask:

> "What ChaosKB tools are available?"

If ChaosKB is working, the agent will list the available tools:

**Knowledge base:** `kb_ingest`, `kb_query`, `kb_list`, `kb_delete`, `kb_summary`, `kb_query_shared`

**Sync & devices:** `kb_sync_status`, `device_link_start`, `device_link_confirm`, `devices_list`, `devices_remove`

**Key management:** `rotate_key`, `audit_log`, `revoke_all`

You can also check which agents have ChaosKB registered:

```bash
chaoskb-mcp status
```

## Multiple agents

ChaosKB can be registered with multiple agents simultaneously. They all share the same local database and encryption keys. Only one agent can run `chaoskb-mcp` at a time — if you switch agents, close the first one before opening the second.

## Removing registration

To remove ChaosKB from all agent configs without deleting your data:

```bash
chaoskb-mcp unregister
```

To remove ChaosKB entirely — agent registrations and all local data:

```bash
chaoskb-mcp uninstall
```

`uninstall` is interactive. It shows exactly what will be deleted (which agent config files will be modified and the `~/.chaoskb/` data directory) and asks for confirmation before proceeding.

## Getting help

```bash
chaoskb-mcp help                   # list all commands
chaoskb-mcp --help                 # same
chaoskb-mcp <command> --help       # help for a specific command
```
