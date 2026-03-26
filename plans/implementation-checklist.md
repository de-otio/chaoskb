# ChaosKB Implementation Checklist

Last updated: 2026-03-26

Reference: [../temp/TODO.md](../temp/TODO.md) for priority rationale.

**Status: ALL PHASES COMPLETE (items 1-10). Only manual QA (item 3) remains as a user task.**

---

## 1. Replace stub tokenizer with real WordPiece tokenizer -- DONE

**Why first:** Semantic search produces garbage results without this. Everything downstream depends on meaningful embeddings.

**Files to modify:**
- `src/pipeline/embedder.ts` — replace `simpleTokenize()` (lines 214-232)
- `src/pipeline/tokenizer.ts` — replace heuristic `countTokens()`

**Files to add:**
- `src/pipeline/wordpiece-tokenizer.ts` — new module

**Steps:**

- [ ] **1.1 — Obtain the model vocabulary**
  - Download `tokenizer.json` and `vocab.txt` from [HuggingFace snowflake-arctic-embed-s](https://huggingface.co/Snowflake/snowflake-arctic-embed-s/tree/main)
  - Determine if the model uses WordPiece (BERT-style) or SentencePiece — check `tokenizer_config.json`
  - Decide: bundle vocab in the package, or download alongside ONNX model via `ModelManager`

- [ ] **1.2 — Extend ModelManager to download tokenizer assets**
  - `src/pipeline/model-manager.ts`: add `TOKENIZER_URL` and `VOCAB_URL` constants
  - Add `ensureTokenizer()` method that downloads `tokenizer.json` (or `vocab.txt`) to `~/.chaoskb/models/`
  - Add SHA-256 verification for tokenizer files (same pattern as model)
  - Update `ensureModel()` to also call `ensureTokenizer()` so both are fetched together

- [ ] **1.3 — Implement WordPiece tokenizer**
  - Create `src/pipeline/wordpiece-tokenizer.ts`
  - Parse the vocabulary file into a `Map<string, number>` (token → ID)
  - Implement the WordPiece algorithm:
    1. Lowercase + strip accents (match model's preprocessing)
    2. Split on whitespace and punctuation
    3. For each word, greedily match longest vocab prefix, then `##` suffixes
    4. Map to integer IDs
    5. Prepend `[CLS]` (101), append `[SEP]` (102)
    6. Truncate to `MAX_SEQ_LENGTH` (512)
  - Export: `tokenize(text: string, vocabPath: string): bigint[]`
  - Export: `countTokensAccurate(text: string, vocabPath: string): number`
  - Handle unknown tokens with `[UNK]` (100)

- [ ] **1.4 — Wire tokenizer into Embedder**
  - `src/pipeline/embedder.ts`: import new tokenizer
  - Replace `simpleTokenize(text)` call in `embedBatch()` with real tokenizer
  - Pass vocab path to `Embedder` constructor (or load once on `initialize()`)
  - Remove the old `simpleTokenize()` function entirely

- [ ] **1.5 — Update approximate token counter**
  - `src/pipeline/tokenizer.ts`: replace heuristic with real WordPiece count
  - Or: keep heuristic for fast chunking decisions, but note discrepancy
  - Decision point: is the 1.3x multiplier close enough, or does chunking need exact counts?

- [ ] **1.6 — Update tests**
  - Update `src/pipeline/__tests__/embedder.test.ts` — embeddings should now be semantically meaningful
  - Update `src/pipeline/__tests__/tokenizer.test.ts` — verify real token counts
  - Add test: tokenize known sentence, verify token IDs match Python HuggingFace output
  - Add test: `[CLS]`/`[SEP]` wrapping, truncation at 512, `[UNK]` handling

- [ ] **1.7 — Verify embedding quality**
  - Write a quick sanity test: embed "dog" and "puppy", embed "dog" and "javascript"
  - Assert cosine similarity of dog/puppy > dog/javascript
  - This proves the tokenizer is producing meaningful model input

---

## 2. End-to-end integration test -- DONE

**Why:** Modules are tested in isolation. Need to prove the full pipeline works as a unit.

**Files to add:**
- `src/__tests__/e2e-pipeline.test.ts`

**Steps:**

- [ ] **2.1 — Create test fixture**
  - Write a small HTML page (~500 words) as a string or fixture file
  - Include varied content: headings, paragraphs, links, code blocks

- [ ] **2.2 — Implement round-trip test**
  - Spin up a local HTTP server (Node `http.createServer`) serving the fixture HTML
  - Call the full ingest pipeline: fetch → extract → chunk → embed → encrypt → store in temp SQLite
  - Assert: source record created, chunks stored, embeddings non-zero, sync status = `local_only`

- [ ] **2.3 — Test search round-trip**
  - Load embedding index from the just-populated DB
  - Query with a phrase from the fixture content
  - Assert: top result is a chunk from the ingested source
  - Assert: result includes source ID, chunk index, score > 0.5

- [ ] **2.4 — Test delete round-trip**
  - Soft-delete the source
  - Assert: source has `deleted_at`, still in DB
  - Assert: search no longer returns chunks from deleted source

- [ ] **2.5 — Test export round-trip**
  - Export the DB (encrypted format)
  - Verify the export file is valid and non-empty
  - (Import test blocked until import is implemented — see item 5)

---

## 3. Manual QA / first real run

**Why:** Tests use mocks and fixtures. Need to validate against real-world content.

**Steps:**

- [ ] **3.1 — Run setup**
  - `node src/dist/cli/index.js setup`
  - Walk through security tier selection
  - Verify config written to `~/.chaoskb/config.json`
  - Verify model downloads on first run

- [ ] **3.2 — Ingest a real article**
  - Use MCP mode or add a temporary CLI `ingest <url>` command
  - Try 3-4 URLs: a blog post, a docs page, a Wikipedia article, a paywalled site (expect graceful failure)
  - Note: content extraction quality, chunk sizes, timing

- [ ] **3.3 — Search**
  - Query for concepts mentioned in ingested articles
  - Verify results are relevant (this validates the tokenizer fix)
  - Test edge cases: very short query, very long query, typos

- [ ] **3.4 — List and delete**
  - List all sources, verify metadata (title, tags, chunk count)
  - Delete one source, verify it disappears from search

- [ ] **3.5 — Register with Claude Desktop**
  - `node src/dist/cli/index.js register --agent claude`
  - Verify Claude Desktop config updated
  - Restart Claude Desktop, verify tools appear
  - Ingest and search via Claude conversation

- [ ] **3.6 — Document issues**
  - Log any bugs, UX rough edges, or missing error messages
  - Feed back into this checklist or create GitHub issues

---

## 4. SSH agent signing -- DONE

**Why:** macOS users typically have keys in ssh-agent only. File-based fallback won't work for them.

**Files to modify:**
- `src/sync/ssh-signer.ts` — implement `signWithAgent()`

**Steps:**

- [ ] **4.1 — Research approach**
  - Option A: Implement SSH agent protocol (RFC 4253 §4) over Unix socket directly
  - Option B: Use `ssh2` npm package (has agent support built in)
  - Option C: Shell out to `ssh-keygen -Y sign` (simplest, requires OpenSSH 8.0+)
  - Decision: weigh binary size vs complexity vs portability

- [ ] **4.2 — Implement chosen approach**
  - Connect to `SSH_AUTH_SOCK` Unix domain socket
  - Send `SSH_AGENTC_SIGN_REQUEST` (byte 13) with public key blob + data
  - Parse `SSH_AGENT_SIGN_RESPONSE` (byte 14) to extract signature
  - Handle `SSH_AGENT_FAILURE` (byte 5) gracefully

- [ ] **4.3 — Update SSHSigner class**
  - `src/sync/ssh-signer.ts`: replace the stub `signWithAgent()` with real implementation
  - Keep the fallback chain: try agent first, then key file
  - Add logging for which method was used

- [ ] **4.4 — Test**
  - Unit test with mock Unix socket
  - Manual test: add key to ssh-agent, remove key file, verify signing works
  - Test fallback: unset `SSH_AUTH_SOCK`, verify file-based signing still works
  - Test error: agent running but key not loaded → should fall back to file

---

## 5. Import / restore flow -- DONE

**Why:** Export without import is a one-way door. Data portability promise requires both directions.

**Files to add:**
- `src/cli/commands/import.ts`
- `src/cli/tools/kb-import.ts` (optional MCP tool)
- `src/__tests__/import.test.ts`

**Files to modify:**
- `src/cli/index.ts` — register import command
- `src/cli/mcp-server.ts` — optionally register `kb_import` tool

**Steps:**

- [ ] **5.1 — Define import format**
  - Read `src/cli/commands/export.ts` to understand the export format exactly
  - Determine: is it a SQLite dump? JSON? Encrypted archive?
  - Document the round-trip contract: export format → import parser

- [ ] **5.2 — Implement import command**
  - Create `src/cli/commands/import.ts`
  - Accept file path and optional passphrase (for encrypted exports)
  - Parse export file, decrypt if needed
  - For each source: insert into DB (skip duplicates by URL or ID)
  - For each chunk: insert with embeddings intact (no need to re-embed)
  - Update embedding index after bulk insert

- [ ] **5.3 — Handle conflicts**
  - If source ID already exists: skip, overwrite, or prompt?
  - Suggested: skip duplicates by default, `--overwrite` flag to replace
  - Log: imported N sources, skipped M duplicates

- [ ] **5.4 — Register CLI command**
  - `src/cli/index.ts`: add `import <file>` command with `--passphrase` and `--overwrite` options

- [ ] **5.5 — Test round-trip**
  - Export a populated DB → import into a fresh DB → verify identical content
  - Test encrypted export → import with correct passphrase
  - Test encrypted export → import with wrong passphrase (expect clear error)
  - Test import with duplicate sources (verify skip behavior)

- [ ] **5.6 — (Optional) Add MCP tool**
  - `kb_import` tool so agents can trigger import
  - Params: `file_path`, `passphrase?`, `overwrite?`
  - Decision: is this useful, or is import always a manual operation?

---

## 6. License decision -- DONE

**Files to modify:**
- `README.md` — line 84, replace "TBD"
- `LICENSE` — update content if changing from MIT

**Steps:**

- [ ] **6.1 — Decide on license**
  - `package.json` (root and `src/`) already says MIT
  - If MIT is the intent, just update README
  - If a different license is desired (e.g., AGPL for server, MIT for client), update all `package.json` files and `LICENSE`

- [ ] **6.2 — Make it consistent**
  - Ensure `README.md`, `LICENSE`, root `package.json`, `src/package.json`, and `server/package.json` all agree

---

## 7. Full-text keyword search (SQLite FTS5) -- DONE

**Files to modify:**
- `src/storage/schema.ts` — add FTS5 virtual table
- `src/storage/chunk-repo.ts` — populate FTS index on insert
- `src/pipeline/search.ts` — add keyword search function
- `src/cli/tools/kb-query.ts` — add `mode` parameter

**Steps:**

- [ ] **7.1 — Add FTS5 virtual table**
  - `src/storage/schema.ts`: add `CREATE VIRTUAL TABLE chunks_fts USING fts5(content, content=chunks, content_rowid=rowid)`
  - Add triggers to keep FTS in sync: `AFTER INSERT`, `AFTER DELETE` on `chunks`
  - Add to schema initialization (migration-safe — check if table exists first)

- [ ] **7.2 — Implement keyword search**
  - `src/pipeline/search.ts` or new `src/storage/fts-search.ts`
  - Function: `searchKeyword(db, query, topK) → {sourceId, chunkIndex, snippet, rank}[]`
  - Use FTS5 `MATCH` with `bm25()` ranking
  - Use `snippet()` function for highlighted excerpts

- [ ] **7.3 — Add hybrid search mode**
  - `src/cli/tools/kb-query.ts`: accept `mode: "semantic" | "keyword" | "hybrid"`
  - Default: `"semantic"` (preserve current behavior)
  - Hybrid: run both, merge results with weighted scoring (e.g., 0.7 semantic + 0.3 keyword)
  - Deduplicate chunks that appear in both result sets

- [ ] **7.4 — Update MCP tool schema**
  - `src/cli/mcp-server.ts`: add `mode` parameter to `kb_query` tool definition
  - Update tool description to explain search modes

- [ ] **7.5 — Test**
  - FTS5 indexing: insert chunks, verify FTS table populated
  - Keyword search: exact phrase match, partial match, boolean operators
  - Hybrid: verify deduplication, verify weighted ranking
  - Edge cases: empty query, special characters, very long query

---

## 8. Multi-device sync conflict resolution -- DONE

**Files to modify:**
- `src/sync/incremental-sync.ts`
- `src/storage/kb-database.ts` (possibly)

**Steps:**

- [ ] **8.1 — Define conflict scenarios**
  - Same source edited on two devices (metadata change: tags, title)
  - Same source deleted on one device, edited on another
  - New source with same URL added on two devices independently

- [ ] **8.2 — Choose a strategy**
  - **Last-write-wins (LWW):** simplest, compare `updated_at` timestamps
  - **Keep-both:** create duplicate entries, let user merge
  - **Prompt user:** surface conflicts via `kb_conflicts` tool or CLI command
  - Recommended: LWW for metadata, keep-both for independent ingests of same URL

- [ ] **8.3 — Implement conflict detection**
  - During incremental sync download, compare server blob timestamps with local
  - Flag conflicts: local `updated_at` > server `updated_at` AND local has unsynchronized changes

- [ ] **8.4 — Implement resolution**
  - Apply chosen strategy automatically for LWW cases
  - Store unresolved conflicts in a new `conflicts` table or status field
  - Surface via `status` command: "2 sync conflicts need attention"

- [ ] **8.5 — Test**
  - Simulate two-device scenario with two SQLite databases and one server
  - Verify LWW picks the right version
  - Verify delete+edit conflict is handled gracefully

---

## 9. Windows support -- DONE

**Files to modify:**
- `src/crypto/keyring.ts` — fix Windows credential retrieval
- `.github/workflows/ci.yml` — add Windows to matrix

**Steps:**

- [ ] **9.1 — Add Windows to CI**
  - `.github/workflows/ci.yml`: add `windows-latest` to the OS matrix
  - Expect failures — this is to discover what breaks

- [ ] **9.2 — Fix path handling**
  - Audit all uses of `path.join()`, `homedir()`, `process.env.HOME`
  - Ensure `~/.chaoskb/` resolves to `%USERPROFILE%\.chaoskb\` on Windows
  - Check SQLite path handling with backslashes

- [ ] **9.3 — Fix Windows keyring**
  - `src/crypto/keyring.ts`: test and fix PowerShell credential commands
  - Use `cmdkey` or `powershell -Command "Get-StoredCredential"` as appropriate
  - Or: use `keytar` npm package for cross-platform keyring access

- [ ] **9.4 — Fix SSH key paths**
  - Default SSH key path on Windows: `%USERPROFILE%\.ssh\id_ed25519`
  - `src/sync/ssh-signer.ts`: ensure constructor default works on Windows
  - SSH agent on Windows uses named pipes, not Unix sockets — flag as unsupported or implement

- [ ] **9.5 — Verify all tests pass on Windows CI**

---

## 10. Binary wire format (CBOR) -- DONE

**Files to modify:**
- `src/crypto/envelope.ts` — add CBOR serialization
- `src/sync/http-client.ts` — negotiate content type
- Server blob routes — accept both JSON and CBOR

**Steps:**

- [ ] **10.1 — Add CBOR dependency**
  - Evaluate: `cbor-x` (fast, maintained) vs `cborg` (smaller)
  - Add to `src/package.json`

- [ ] **10.2 — Implement CBOR envelope**
  - `src/crypto/envelope.ts`: add `serializeCBOR()` and `deserializeCBOR()` alongside existing JSON methods
  - Binary ciphertext stored directly (no base64), saving ~33% size

- [ ] **10.3 — Version the format**
  - Add `format: 1` (JSON) or `format: 2` (CBOR) field to envelope header
  - Reader must handle both — old JSON envelopes must still deserialize

- [ ] **10.4 — Update sync client**
  - `src/sync/http-client.ts`: send `Content-Type: application/cbor` for new blobs
  - Server accepts both `application/json` and `application/cbor`
  - Incremental sync: downloaded blobs may be either format

- [ ] **10.5 — Update server blob handler**
  - `server/lib/handler/routes/blobs.ts`: detect content type, parse accordingly
  - Store blobs opaquely — server doesn't need to know the format

- [ ] **10.6 — Test**
  - Round-trip: CBOR serialize → deserialize → compare with original
  - Backward compat: ensure old JSON envelopes still work
  - Size comparison: measure actual savings on a real dataset

---

## Quick-reference: suggested order

| Phase | Items | Goal |
|-------|-------|------|
| **Phase 1: Make it work** | 1, 2, 3, 6 | DONE (3 = manual QA, user task) |
| **Phase 2: Make it complete** | 4, 5 | DONE |
| **Phase 3: Make it better** | 7, 8 | DONE |
| **Phase 4: Make it broad** | 9, 10 | DONE |
