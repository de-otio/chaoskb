# ChaosKB — Remaining Work Plan

Last updated: 2026-03-26

Two npm packages to publish:
- `@deotio/chaoskb-client` (src/) — CLI + MCP server for end users
- `@deotio/chaoskb-server` (server/) — CDK construct library consumed by chaoskb-internal and self-hosters

---

## 1. Prepare packages for npm publish

### 1.1 — Client package (`src/package.json`)

- [ ] Add `prepublishOnly` script: `"npm run build"` to ensure `dist/` is fresh
- [ ] Add `prepack` script: `"chmod +x dist/cli/index.js"` to set executable permission on the binary
- [ ] Add `publishConfig`: `{ "access": "public" }` (required for scoped `@deotio` packages on public npm)
- [ ] Verify the shebang (`#!/usr/bin/env node`) is present in `dist/cli/index.js`
- [ ] Verify `dist/cli/index.d.ts` exists (TypeScript consumers need it)

### 1.2 — Server package (`server/package.json`)

- [ ] Add `prepublishOnly` script: `"npm run build"` to ensure `dist/` is fresh
- [ ] Add `publishConfig`: `{ "access": "public" }`
- [ ] Verify `dist/lib/index.js` and `dist/lib/index.d.ts` exist after build
- [ ] Verify the `files` field (`["dist"]`) includes the handler source files that the build script copies
- [ ] Confirm `peerDependencies` for `aws-cdk-lib` and `constructs` are correct version ranges
- [ ] Verify the package works when consumed externally: `npm pack`, install in a temp CDK app, import `ChaosKBStack`

### 1.3 — Decide on vocab.txt bundling strategy (client only)

**Decision needed:** The vocab.txt file is 30,522 lines (~300KB). Two options:
- **Bundle it** in the npm package (add to `files`): simpler, works offline, adds ~300KB to package size
- **Download at runtime** via `ModelManager.ensureVocab()`: smaller package, but requires network on first use (already implemented)

If downloading at runtime: no changes needed — `ModelManager` already handles this.
If bundling: add `"pipeline/vocab.txt"` to `files` in `src/package.json` and update the tokenizer to resolve it relative to `__dirname`.

### 1.4 — Verify package contents for both packages

- [ ] Run `cd src && npm pack` — inspect tarball contains `dist/`, `package.json`, nothing else unwanted
- [ ] Run `cd server && npm pack` — inspect tarball contains `dist/`, `package.json`, handler source files
- [ ] Install each tarball in a temp directory and verify basic imports work

### 1.5 — Add npm publish CI workflow

**File:** `.github/workflows/publish.yml` (new)

- [ ] Create a publish workflow that triggers on GitHub releases (tags matching `v*`)
- [ ] Publish **both** packages in sequence:
  1. `cd server && npm publish` (server first — no dependencies on client)
  2. `cd src && npm publish` (client second)
- [ ] Steps: checkout → setup Node 20 → `npm ci` → build both → publish both
- [ ] Use `NODE_AUTH_TOKEN` secret for npm authentication
- [ ] Add `access=public` via `.npmrc` or `publishConfig` in each package
- [ ] Consider: version bump strategy — manual in package.json, or use `npm version` in CI?
- [ ] Consider: publish dry-run step on PRs to catch issues early

### 1.6 — Create .npmrc for publish settings

**File:** `src/.npmrc` and `server/.npmrc` (new)

- [ ] Add `access=public` to both so scoped packages publish publicly by default

### 1.7 — Test the full publish flow locally

**Client:**
- [ ] `cd src && npm pack` and inspect the tarball
- [ ] `npm publish --dry-run` to verify it would succeed
- [ ] Install the tarball in a temp directory: `npm install ./deotio-chaoskb-client-0.1.0.tgz`
- [ ] Run `npx chaoskb-mcp --version` from the installed package

**Server:**
- [ ] `cd server && npm pack` and inspect the tarball
- [ ] `npm publish --dry-run` to verify it would succeed
- [ ] Install in a temp CDK project: `npm install ./deotio-chaoskb-server-0.1.0.tgz`
- [ ] Import and instantiate `ChaosKBStack` in a minimal CDK app — verify it synthesizes

---

## 2. Fix README and docs for npm-only install

### 2.1 — Update README install instructions

**File:** `README.md`

- [ ] Remove references to Rust binary (`chaoskb-mcp` as "self-contained Rust binary")
- [ ] Update Clients section to describe the npm package:
  ```
  - **Desktop** — `@deotio/chaoskb-client`, an npm package that runs as an MCP server
  ```
- [ ] Add install instructions:
  ```bash
  npm install -g @deotio/chaoskb-client
  chaoskb-mcp setup
  ```
- [ ] Remove or update any references to `brew install` or `cargo install`
- [ ] Update self-hosting section to reference the server package:
  ```bash
  npm install @deotio/chaoskb-server
  ```

### 2.2 — Update getting-started guide

**File:** `doc/user/getting-started.md`

- [ ] Ensure install steps reference `npm install -g @deotio/chaoskb-client`
- [ ] Verify the setup walkthrough matches current `chaoskb-mcp setup` behavior

---

## 3. Manual QA — first real run

### 3.1 — Run setup

- [ ] `chaoskb-mcp setup` — walk through security tier selection
- [ ] Verify config written to `~/.chaoskb/config.json`
- [ ] Verify ONNX model downloads on first run (~134MB)
- [ ] Verify vocab.txt downloads alongside the model

### 3.2 — Ingest real articles

- [ ] Ingest a blog post, a docs page, a Wikipedia article
- [ ] Try a paywalled site (expect graceful failure)
- [ ] Note: content extraction quality, chunk sizes, timing

### 3.3 — Search

- [ ] Semantic search: query for concepts in ingested articles, verify relevance
- [ ] Keyword search: `mode: "keyword"`, verify exact phrase matching
- [ ] Hybrid search: `mode: "hybrid"`, verify combined results
- [ ] Edge cases: very short query, very long query, typos

### 3.4 — MCP integration

- [ ] `chaoskb-mcp register --agent claude` — verify Claude Desktop config updated
- [ ] Restart Claude Desktop, verify tools appear
- [ ] Ingest and search via Claude conversation

### 3.5 — Document issues

- [ ] Log any bugs, UX rough edges, or missing error messages
- [ ] Create GitHub issues for anything found

---

## 4. Verify real embeddings work

### 4.1 — Test with actual ONNX model

- [ ] Download the snowflake-arctic-embed-s model (`ModelManager.ensureModel()`)
- [ ] Embed known sentences: "dog", "puppy", "javascript framework"
- [ ] Verify cosine similarity of dog/puppy > dog/javascript
- [ ] This proves the WordPiece tokenizer produces meaningful model input

### 4.2 — Benchmark search performance

- [ ] Ingest 50-100 articles
- [ ] Measure search latency (target: <50ms for semantic, <10ms for keyword)
- [ ] Measure memory usage of embedding index

---

## 5. Server deployment

### 5.1 — Test CDK deployment

- [ ] Run `npx chaoskb-deploy` against a real AWS account
- [ ] Verify Lambda + DynamoDB + Cognito resources created
- [ ] Verify function URL is accessible

### 5.2 — End-to-end sync test

- [ ] Configure client to point at deployed server (`chaoskb-mcp setup-sync`)
- [ ] Ingest an article, verify it syncs to DynamoDB
- [ ] Set up a second device, verify incremental sync downloads the article
- [ ] Test conflict: edit on both devices, verify resolution

---

## 6. Encrypted import

### 6.1 — Implement encrypted import

**File:** `src/cli/commands/import.ts`

- [ ] Add support for the encrypted export format (JSON with Argon2id-wrapped key)
- [ ] Prompt for passphrase, derive wrapping key, unwrap master key
- [ ] Decrypt envelope payloads and insert into database
- [ ] Test round-trip: encrypted export → encrypted import

---

## 7. MCP server startup path

### 7.1 — Add integration test for MCP startup

- [ ] Test that `initializeDependencies()` in `mcp-server.ts` doesn't crash
- [ ] Mock the keyring (to avoid requiring OS keyring in CI)
- [ ] Verify the server creates a valid MCP Server instance
- [ ] Verify all 5 tools are registered and callable

---

## Suggested order

| Priority | Items | What you get |
|----------|-------|-------------|
| **Now** | 1 (npm publish prep — both packages) | Users can `npm install`, chaoskb-internal can consume server |
| **Now** | 2 (fix docs) | Install instructions are accurate |
| **Next** | 3, 4 (manual QA + real embeddings) | Confidence it actually works |
| **Then** | 5 (server deployment) | Multi-device sync works |
| **Later** | 6, 7 (encrypted import, MCP startup test) | Polish |
