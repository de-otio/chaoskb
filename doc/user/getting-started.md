# Getting Started

Install ChaosKB and save your first article in under 5 minutes.

## Install

```bash
npm install -g @deotio/chaoskb-client
```

Then set up and register with your chat agents:

```bash
chaoskb-mcp setup && chaoskb-mcp register
```

This auto-detects installed agents (Claude Desktop, Cursor, VS Code, etc.) and registers ChaosKB in their MCP configs.

## First run

Open your chat agent. On first launch, ChaosKB will:

1. Download the embedding model (~134 MB, one-time)
2. Create a local database at `~/.chaoskb/local.db`
3. Report its tools as available to the agent

This takes 30-60 seconds on first run, 1-3 seconds on subsequent launches.

## Save your first article

Ask your chat agent:

> "Save https://example.com/some-interesting-article to my knowledge base"

The agent calls `kb_ingest`, which:
- Fetches and extracts the article content
- Splits it into searchable chunks
- Computes embeddings on your device
- Stores everything locally

You'll see a confirmation like: *Ingested "Article Title" (12 chunks)*

## Search your knowledge base

Ask your agent:

> "Search my knowledge base for articles about Rust ownership"

The agent calls `kb_query`, which searches your local embeddings and returns the most relevant chunks with their source articles.

## That's it

ChaosKB works fully offline with just these two operations. Everything stays on your device.

## Enable backup and sync (free)

ChaosKB includes a free sync plan (50 MB, ~925 articles) for backup and multi-device access:

```bash
chaoskb-mcp setup sync
```

This registers your SSH public key with the hosted service. Authentication is automatic (Ed25519 via ssh-agent or `~/.ssh/id_ed25519`). No email or password needed.

Once configured, articles sync in the background after every ingest. You can also [deploy your own server](../admin/deploy.md) instead.

Sync is optional and can be added or removed at any time without affecting your local data.

## Optional: choose a security tier

By default, ChaosKB uses **Standard** tier — your data is end-to-end encrypted, with the master key wrapped by your SSH public key. Recovery requires your SSH private key. If you need additional protection, you can upgrade to **Enhanced** (recovery key + SSH key) or **Maximum** (passphrase) at any time. See [Security Tiers](security-tiers.md).

## Check your setup

```bash
chaoskb-mcp status
```

Shows your current configuration, registered agents, security tier, and storage usage.
