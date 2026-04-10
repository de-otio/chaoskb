# Project Knowledge Bases

By default, ChaosKB stores everything in a single personal knowledge base. Project KBs let you create isolated, scoped knowledge bases for specific work — a codebase, a research topic, a client engagement.

## Why use project KBs?

- **Context scoping.** When you query a project KB, results come only from that project's articles. No noise from unrelated saved content.
- **Workspace integration.** Project KBs register in workspace-level agent configs (`.vscode/mcp.json`, `.cursor/mcp.json`), so the right KB is active when you open a project.
- **Disposable.** Done with a project? Delete the KB. Your personal KB is untouched.
- **Independent encryption.** Each project has its own encryption key. This enables sharing project KBs with collaborators in the future without exposing your personal KB.

## Create a project KB

```bash
chaoskb-mcp project create acme-api
```

This creates `~/.chaoskb/projects/acme-api/local.db` with its own encryption key and embedding index.

## Register with your agent

```bash
chaoskb-mcp register --project acme-api
```

For workspace-aware agents (Cursor, VS Code), this writes to the project-level config (e.g., `.vscode/mcp.json`) rather than the global config. The agent only sees the project KB when working in that workspace.

For agents without workspace configs (Claude Desktop), the project KB is registered globally alongside your personal KB as a separate named server (`chaoskb-acme-api`).

After registration, your agent's MCP config looks like:

```json
{
  "mcpServers": {
    "chaoskb": {
      "command": "chaoskb-mcp",
      "args": [],
      "env": {}
    },
    "chaoskb-acme-api": {
      "command": "chaoskb-mcp",
      "args": ["--project", "acme-api"],
      "env": {}
    }
  }
}
```

Restart your agent after registration.

## Using a project KB

Once registered, your agent sees the project KB as a separate set of tools. Ask naturally:

> "Save https://docs.example.com/api-reference to the acme-api knowledge base"

> "Search the acme-api KB for authentication flow"

The agent routes to the correct KB based on context. If both your personal KB and a project KB are registered, you can specify which one:

> "Search my personal knowledge base for OAuth best practices"

> "Search acme-api for our API rate limits"

All the same knowledge base tools are available — `kb_ingest`, `kb_query`, `kb_list`, `kb_delete`, `kb_summary` — scoped to whichever KB the agent calls. For shared project KBs, `kb_query_shared` provides results with attribution (who added the article). See the [MCP Tools Reference](mcp-tools.md) for full details.

## Cross-project search

To search across all your knowledge bases at once:

> "Search all my knowledge bases for articles about encryption"

When the agent calls `kb_query` without specifying a `kb` parameter, it searches across your personal KB and all project KBs simultaneously, merging results by relevance score.

## Managing project KBs

### List projects

```bash
chaoskb-mcp project list
```

Shows all local project KBs with their article count and storage size.

### Delete a project

```bash
chaoskb-mcp project delete acme-api
```

Removes the project directory (`~/.chaoskb/projects/acme-api/`) after confirmation. This is permanent — the data is deleted from your device. If the project was synced to a server, the server copy is also marked for deletion.

Your personal KB and other project KBs are unaffected.

## How it works

Each project KB is a separate SQLite database with its own encryption key and in-memory embedding index. When your agent starts a project KB's MCP server (`chaoskb-mcp --project acme-api`), only that project's data is loaded. This keeps startup fast and memory usage proportional to the active project.

Project encryption keys are independent random keys, not derived from your personal master key. Each project key is wrapped (encrypted) with your personal master key and stored alongside your personal KB data. If you recover your personal master key, all project keys are recoverable too.

## Sync

Project KBs sync just like your personal KB. If you've configured sync (`chaoskb-mcp setup sync`), each project KB syncs to its own server tenant automatically. Project KB storage counts against your sync quota (50 MB on the free plan, across all KBs).

If your quota is full, sync pauses but everything continues to work locally. Other members of a shared project are unaffected.

## What's coming

- **Shared project KBs** — invite collaborators to a project KB. They get the project key via secure key exchange. No re-encryption of existing data needed.
