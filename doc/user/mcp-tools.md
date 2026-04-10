# MCP Tools Reference

ChaosKB provides 14 tools to your chat agent, organized into three groups. You don't call these directly — you ask your agent in natural language and it calls the right tool.

## Knowledge base tools

### kb_ingest — Save a URL or file

Fetches a URL or reads a local file, extracts text, chunks it, computes embeddings, and stores everything locally.

**Example prompts:**
- "Save this article: https://example.com/rust-ownership"
- "Add https://example.com/article to my knowledge base and tag it as 'rust'"
- "Ingest this PDF into my KB: ~/Documents/paper.pdf"

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `url` | One of `url` or `filePath` | URL to fetch and ingest |
| `filePath` | One of `url` or `filePath` | Local file path (PDF, DOCX, PPTX, HTML, TXT, MD) |
| `tags` | No | Tags to assign (e.g., `["rust", "programming"]`) |
| `kb` | No | Named KB to ingest into (defaults to active KB) |

**What happens:**
1. The content is fetched/read and text is extracted on your device
2. Text is split into chunks (~500 tokens each)
3. Each chunk is embedded using the on-device model
4. Everything is encrypted and stored locally (searchable immediately)
5. If server sync is configured, encrypted blobs upload in the background

**Supported file formats:** PDF, DOCX, PPTX, HTML, plain text, Markdown.

**Response:** `Ingested "Article Title" (12 chunks)`

### kb_query — Search your knowledge base

Searches your saved articles using natural language. Supports semantic (embedding) search, keyword (FTS5) search, or hybrid (both combined).

**Example prompts:**
- "Search my knowledge base for articles about Rust ownership"
- "What have I saved about database indexing?"
- "Find articles about encryption using keyword search"

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `query` | Yes | Natural language search query |
| `limit` | No | Maximum results to return (default: 10) |
| `mode` | No | `"semantic"` (default), `"keyword"` for exact text match, or `"hybrid"` for combined ranking |
| `kb` | No | Named KB to search (omit to search all KBs) |

When you omit the `kb` parameter and have multiple knowledge bases, results are merged across all KBs and ranked by score.

**Response:** Ranked list of matching chunks with their source article title, URL, and relevance score.

### kb_list — List saved articles

Lists all saved sources with metadata.

**Example prompts:**
- "List my saved articles"
- "Show me the last 20 articles I saved"
- "List articles tagged 'rust'"

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `limit` | No | Maximum articles to return (default: 20) |
| `offset` | No | Skip this many articles (for pagination) |
| `tags` | No | Filter by tags (e.g., `["rust"]`) |
| `kb` | No | Named KB to list (omit to list all KBs) |

**Response:** List of articles with title, URL, save date, and chunk count.

### kb_delete — Delete an article

Soft-deletes an article and its chunks from the knowledge base. Deleted items go to trash for 30 days before permanent removal.

**Example prompts:**
- "Delete the article about Rust ownership from my knowledge base"
- "Remove this article from my KB: [article ID]"

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `id` | Yes | The article ID to delete |

The agent will typically look up the article first (via `kb_list` or `kb_query`) to find the correct ID.

**Response:** Confirmation of deletion. Items can be restored from trash within 30 days.

### kb_summary — Summarize recent saves

Returns articles saved during a time period for the agent to summarize.

**Example prompts:**
- "Summarize what I saved this week"
- "What did I add to my knowledge base last month?"
- "Give me an overview of my reading this year"

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `period` | Yes | `"week"`, `"month"`, `"year"`, or a custom range like `"2026-01-01:2026-06-30"` |

**Response:** Structured list of articles with titles, URLs, dates, and a preview of each article's content. The agent uses this to generate a summary.

### kb_query_shared — Search a shared project KB

Like `kb_query` but for shared project knowledge bases. Includes content attribution (project name, uploader) in each result for provenance tracking.

**Example prompts:**
- "Search the team-docs project for onboarding guides"
- "Find API rate limit docs in the acme-api shared KB"

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `query` | Yes | Search query |
| `project` | Yes | Shared project name to search |
| `limit` | No | Maximum results to return (default: 10) |
| `mode` | No | `"semantic"` (default), `"keyword"`, or `"hybrid"` |

**Response:** Ranked results with source attribution (who added the article, from which project).

## Sync & device tools

### kb_sync_status — Check sync status

Shows sync status, security tier, key type, device count, rotation state, and pending invites.

**Example prompts:**
- "What's my ChaosKB sync status?"
- "Am I syncing? How many devices are linked?"

**Parameters:** None.

**Response:** Summary of sync configuration, tier, and device state.

### device_link_start — Generate a link code

Generates a device link code on this device. Share the code with your new device to link it.

**Example prompts:**
- "I want to add a new device to ChaosKB"
- "Generate a device link code"

**Parameters:** None.

**Response:** A link code to enter on the new device. Expires after a short time.

### device_link_confirm — Confirm a device link

Confirms a device link on the new device by submitting the link code from the existing device.

**Example prompts:**
- "Link this device with code ABC123"
- "Confirm device link: ABC123"

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `linkCode` | Yes | The link code from the existing device |

**Response:** Confirmation that the device is now linked and syncing.

### devices_list — List linked devices

Lists all registered devices for this account with fingerprints and registration dates.

**Example prompts:**
- "Show my linked devices"
- "List all devices on my ChaosKB account"

**Parameters:** None.

**Response:** Device list with fingerprints, names, and registration dates.

### devices_remove — Remove a device

Removes a registered device by fingerprint. The device will stop syncing on its next attempt.

**Example prompts:**
- "Remove my old laptop from ChaosKB"
- "Unlink device with fingerprint SHA256:..."

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `fingerprint` | Yes | Fingerprint of the device to remove |

**Response:** Confirmation that the device has been removed.

## Key management tools

### rotate_key — Rotate your SSH key

Initiates SSH key rotation. Re-wraps the master key with a new SSH key and registers it with the server.

**Example prompts:**
- "Rotate my ChaosKB SSH key"
- "Switch to my new SSH key for ChaosKB"

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `newKeyPath` | No | Path to the new SSH key (auto-detects if omitted) |

**Response:** Confirmation that the key has been rotated.

### audit_log — View security events

Shows the device audit log: registrations, rotations, revocations, and device link events.

**Example prompts:**
- "Show my ChaosKB audit log"
- "What security events have happened on my account?"

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `limit` | No | Maximum number of events to return (default: 50) |

**Response:** Chronological list of security events.

### revoke_all — Emergency revoke all devices

Emergency action: revokes all device keys. All devices lose sync access and must re-register. Requires exact confirmation string.

**Example prompts:**
- "Revoke all devices on my ChaosKB account"

**Parameters:**
| Parameter | Required | Description |
|-----------|----------|-------------|
| `confirmation` | Yes | Must be exactly `"REVOKE ALL"` to confirm |

**Response:** Confirmation that all device keys have been revoked.
