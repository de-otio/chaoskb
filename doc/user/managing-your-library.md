# Managing Your Library

## Search

Ask your chat agent to search in natural language:

> "Search my knowledge base for articles about database performance"

Search is local and fast (<50ms). It works offline — no server connection needed. Results are ranked by relevance to your query.

### Search modes

ChaosKB supports three search modes:

- **Semantic** (default) — finds articles by meaning, even if the exact words don't match. Best for exploratory searches like "articles about memory safety."
- **Keyword** — exact text matching via FTS5. Best when you know the specific term, e.g., "find articles mentioning XChaCha20."
- **Hybrid** — combines both semantic and keyword results. Best for broad searches where you want both conceptual and exact matches.

Ask your agent to use a specific mode:

> "Search my KB for 'borrow checker' using keyword search"
> "Find articles related to database scaling using hybrid mode"

### Search tips

- Use specific terms for precise results: "Rust borrow checker" rather than "programming"
- Search finds content within articles, not just titles
- You can limit results: "Find the top 3 articles about encryption"
- Use keyword mode when you need exact term matches
- Omit the KB name to search across all your knowledge bases at once

## Listing articles

> "List my saved articles"
> "Show me the last 20 articles I saved"

This returns titles, URLs, save dates, and chunk counts.

## Deleting articles

> "Delete the article about Rust ownership"

Deleted articles are soft-deleted and go to **trash** for 30 days. During that time:
- The article is hidden from search results and listings
- Other devices see the deletion on their next sync
- The data can still be recovered

After 30 days, trashed items are permanently removed.

## Storage

### How storage works

Every article you save is split into chunks (~500 tokens each). Each chunk is encrypted and stored as a blob (~4.5 KB). A typical article produces about 12 chunks.

| Library size | Approximate storage |
|-------------|-------------------|
| 100 articles | ~6 MB |
| 1,000 articles | ~58 MB |
| 5,000 articles | ~290 MB |

Local storage (on your device) is unlimited. Synced storage (on the server) depends on your plan.

### Checking storage

Ask your agent:

> "What's my ChaosKB sync status?"

This calls `kb_sync_status` and shows your current storage usage, device count, and sync state.

### When you're running low

At 100% synced storage, everything still works locally — you just won't get new backups until you free space. New articles save and search locally as normal.

To free space, delete articles you no longer need. Deleted items go to trash for 30 days, then are permanently removed and the storage is reclaimed.
