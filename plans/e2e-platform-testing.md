# ChaosKB — Exhaustive End-to-End Platform Testing Plan

Last updated: 2026-03-27 (implemented)

---

## Overview

The client package (`@de-otio/chaoskb-client`) ships three native modules that compile platform-specific binaries:

- **`sodium-native`** — Argon2id key derivation and XChaCha20 encryption via libsodium
- **`better-sqlite3`** — SQLite3 storage engine
- **`onnxruntime-node`** — Embedding model inference

The existing CI workflow covers only generic GitHub-hosted runners (`ubuntu-latest`, `macos-latest`, `windows-latest`), which are all x64. It does **not** cover Linux ARM or macOS Intel (which GitHub now routes to ARM by default via `macos-latest`). A prebuilt binary that works on one architecture silently fails on another — the failure surfaces to real users, not in CI.

This plan adds a dedicated workflow that runs exhaustive end-to-end tests of the installed client binary on all five shipping platforms.

---

## Platform Matrix

| Label | Runner | Arch | Node |
|---|---|---|---|
| linux-x64 | `ubuntu-24.04` | x86_64 | 20, 22 |
| linux-arm64 | `ubuntu-24.04-arm` | aarch64 | 20, 22 |
| macos-intel | `macos-13` | x86_64 | 20, 22 |
| macos-arm | `macos-15` | arm64 (M-series) | 20, 22 |
| windows-x64 | `windows-latest` | x86_64 | 20, 22 |

> `ubuntu-24.04-arm` is a GitHub-hosted ARM64 runner (generally available as of 2024).
> `macos-13` is the last Intel macOS runner; `macos-latest` and `macos-15` are ARM.
> Windows ARM64 runners are not yet generally available; skip for now.

---

## Test Categories

### T1 — Dependency installation

Verify `npm ci` succeeds and all native modules install their prebuilt binaries (or build from source if no prebuilt exists).

- `npm ci` exits 0
- `node -e "require('sodium-native')"` exits 0
- `node -e "require('better-sqlite3')"` exits 0
- `node --input-type=module -e "import('onnxruntime-node')"` exits 0

Failure here means a prebuilt is missing for this platform/arch combo and the package will not install for real users.

### T2 — Build

Verify the TypeScript build produces a runnable binary with the correct shebang.

- `npm run build` (in `src/`) exits 0
- `dist/cli/index.js` exists
- First line of `dist/cli/index.js` is `#!/usr/bin/env node`
- `dist/cli/agent-registry/registry.json` exists (the cp step in the build script)

### T3 — CLI smoke test

Verify the compiled binary responds to basic CLI invocations without crashing.

- `node dist/cli/index.js --help` exits 0 and prints usage
- `node dist/cli/index.js --version` exits 0 and prints a semver string
- On POSIX: the shebang line makes the file self-executable after `chmod +x`; verify `./dist/cli/index.js --help` works

### T4 — Native module correctness

Verify each native module not only loads but produces correct output at the level actually used by the application.

**sodium-native:**
- Generate a random 32-byte key: `sodium.randombytes_buf(buf, 32)` — verify length
- Hash with `crypto_generichash` — verify deterministic output for known input
- Argon2id stretch a passphrase — verify output is 32 bytes (tests the actual key-derivation path used in setup)

**better-sqlite3:**
- Open an in-memory database: `new Database(':memory:')`
- Create a table, insert a row, SELECT it back — verify round-trip
- Enable WAL mode (used by the app) — verify `PRAGMA journal_mode=WAL` returns `wal`
- Test FTS5 virtual table creation (used for keyword search)

**onnxruntime-node:**
- Import `InferenceSession` without error
- Load the `snowflake-arctic-embed-s` model (cached via `actions/cache` — see Model Caching section)
- Run a full inference pass: tokenize two known sentences, embed both, compute cosine similarity
- Assert `similarity("dog", "puppy") > similarity("dog", "javascript framework")` — proves the model produces semantically meaningful vectors on this platform/arch

### T5 — Crypto pipeline

Exercise the full crypto stack end-to-end: key generation → encryption → decryption.

- Generate an Ed25519 keypair (device identity)
- Derive a symmetric key from a known passphrase + salt using Argon2id
- Encrypt a payload with XChaCha20-Poly1305
- Decrypt and verify the plaintext matches

These operations correspond to what `chaoskb-mcp setup` does under the hood. A pass here means the crypto layer works on this platform.

### T6 — Database layer

Exercise the SQLite schema used by the app, not just an in-memory sanity check.

- Initialize the full application schema (call `createSchema()` or equivalent)
- Insert an article, verify it is stored and retrievable
- Run the FTS5 keyword search — verify it returns the inserted article
- Insert an embedding vector (stored as BLOB), verify round-trip binary fidelity
- Run a VACUUM and ANALYZE — verify no errors

### T7 — MCP server startup

Verify the MCP server can start, register its tools, and shut down cleanly.

- Start the server process with `node dist/cli/index.js mcp` via `child_process.spawn`
- Send the MCP `initialize` request over stdin/stdout (JSON-RPC)
- Receive `initialized` response
- Send `tools/list` request
- Verify response contains all expected tool names: `ingest`, `search`, `list`, `delete`, `export`
- Send `shutdown` — verify clean exit

The keyring interaction must be bypassed in CI (no OS keyring available). Use an env var or flag that makes the client fall back to an unencrypted local key file (the "no keyring" tier).

### T8 — Packaged install simulation

Simulate what a real user experiences after `npm install -g @de-otio/chaoskb-client`.

- `npm pack` in `src/` — produces `de-otio-chaoskb-client-*.tgz`
- `npm install -g ./de-otio-chaoskb-client-*.tgz` in a temp directory
- `chaoskb-mcp --help` — verify the globally installed binary runs
- `chaoskb-mcp --version` — verify version matches `package.json`

This catches issues like missing files in the `files` array, broken relative paths, or the shebang not being preserved.

---

## Workflow Design

### File: `.github/workflows/e2e-platforms.yml`

**Trigger:**
- `push` to `master` and `dev`
- `pull_request` targeting `master` or `dev`
- `workflow_dispatch` (manual trigger for ad-hoc runs)

**Structure:**

```
jobs:
  e2e:
    strategy:
      fail-fast: false
      matrix:
        os:
          - ubuntu-24.04
          - ubuntu-24.04-arm
          - macos-13
          - macos-15
          - windows-latest
        node-version: [20, 22]
```

`fail-fast: false` ensures all platform results are visible in a single run rather than aborting early.

**Steps per job:**

1. `actions/checkout@v4`
2. `actions/setup-node@v4` with `node-version: ${{ matrix.node-version }}` and `cache: npm`
3. **T1** — Install: `npm ci`
4. **Restore ONNX model cache** — `actions/cache` keyed on model version + runner arch (see Model Caching section)
5. **T2** — Build: `cd src && npm run build` (or root `npm run build --workspace src`)
6. **T3** — CLI smoke: `node src/dist/cli/index.js --help` and `--version`
7. **T4** — Native module correctness: run a small inline Node script per module (includes full ONNX inference)
8. **T5** — Crypto pipeline: run the test script (see Implementation section)
9. **T6** — Database layer: run the test script
10. **T7** — MCP server startup: run the test script
11. **T8** — Pack and install:
    - `cd src && npm pack`
    - Install to temp dir
    - Run `chaoskb-mcp --help`

**Platform-specific overrides:**

- `macos-13` and `macos-15` may need Xcode command-line tools for native compilation fallback: add `xcode-select --install || true` before `npm ci`
- Windows: use `node src/dist/cli/index.js` everywhere instead of `./dist/cli/index.js` (no shebang execution on Windows). The T3 POSIX shebang check is skipped via `if: runner.os != 'Windows'`
- Linux ARM: no special handling needed — GitHub's ARM runners run standard Ubuntu and the native prebuilts for `sodium-native`, `better-sqlite3`, and `onnxruntime-node` all ship ARM64 variants

---

## Test Script Implementation

Create a directory `src/__e2e__/` with small focused scripts that each test one category. These are not vitest tests — they are plain Node.js ESM scripts that exit 1 on failure so GitHub Actions marks the step as failed.

### `src/__e2e__/native-modules.mjs`
Covers T1 (runtime) + T4.

```
- import sodium from 'sodium-native'
- import Database from 'better-sqlite3'
- import { InferenceSession } from 'onnxruntime-node'
- For each: run a meaningful operation, assert expected output, console.log pass/fail
- process.exit(1) on any assertion failure
```

### `src/__e2e__/crypto-pipeline.mjs`
Covers T5.

```
- Import the app's own Crypto/KeyRing modules from dist/
- Run: keygen → derive → encrypt → decrypt → assert plaintext === original
```

### `src/__e2e__/database-layer.mjs`
Covers T6.

```
- Import storage layer from dist/
- Open a temp DB in a temp directory
- Run the schema creation
- Exercise insert / FTS search / vector blob round-trip
- Cleanup temp dir
```

### `src/__e2e__/mcp-startup.mjs`
Covers T7.

```
- Spawn `node dist/cli/index.js mcp` with env CHAOSKB_KEYRING=none
- Write initialize + tools/list JSON-RPC frames to stdin
- Read and parse stdout, assert tools list contains expected 5 tools
- Send shutdown, assert process exits 0
- Timeout after 10s and exit(1) if no response
```

### `src/__e2e__/pack-install.sh` (and `.ps1` for Windows)
Covers T8 — shell script that:

```
- cd src && npm pack
- mkdir /tmp/chaoskb-install-test && cd /tmp/chaoskb-install-test
- npm install <path-to-tgz>
- ./node_modules/.bin/chaoskb-mcp --help
- ./node_modules/.bin/chaoskb-mcp --version
```

---

## Implementation Steps

1. **Create `src/__e2e__/` directory** and add the four test scripts above.

2. **Add a `test:e2e` script** to `src/package.json`:
   ```json
   "test:e2e": "node --experimental-vm-modules src/__e2e__/native-modules.mjs && node src/__e2e__/crypto-pipeline.mjs && node src/__e2e__/database-layer.mjs && node src/__e2e__/mcp-startup.mjs"
   ```

3. **Add `CHAOSKB_KEYRING=none` support** to the keyring module so it falls back to a temp file rather than the OS keyring. This is needed for T7 and should also be useful for T5/T6 when the keyring is involved. Gate it on the env var so it never affects production behavior.

4. **Create `.github/workflows/e2e-platforms.yml`** with the matrix described above. Keep it separate from `ci.yml` so the existing fast lint/typecheck/unit-test loop is not slowed down.

5. **Verify the `ubuntu-24.04-arm` runner is available** for the repo. If the repo is on a free plan, ARM runners require GitHub Team or Enterprise. In that case, substitute a QEMU-based cross-compilation job using `docker/setup-qemu-action` + `docker run --platform linux/arm64`.

6. **Optional: add a badge** to README for the e2e workflow status.

---

## ONNX Model Caching

The `snowflake-arctic-embed-s` model (~134 MB) must be present for the full embedding end-to-end test in T4. Rather than downloading it fresh on every job, cache it with `actions/cache`.

**Cache key strategy:**

```yaml
- name: Restore ONNX model cache
  uses: actions/cache@v4
  with:
    path: ~/.chaoskb/models
    key: onnx-model-snowflake-arctic-embed-s-${{ runner.arch }}
    restore-keys: |
      onnx-model-snowflake-arctic-embed-s-
```

Keying on `runner.arch` (`X64` or `ARM64`) ensures the cached model file is appropriate for the platform — ONNX model weights are architecture-independent (they are float tensors), but the cache entry is per-arch anyway as a safety measure and to keep cache entries isolated per platform.

**First run behavior:** Cache miss triggers `ModelManager.ensureModel()` during T4, which downloads the model to `~/.chaoskb/models/`. `actions/cache` saves this directory as the new cache entry at the end of the job. Subsequent runs restore it in seconds.

**Cache invalidation:** The key includes the model name. If the app ever upgrades to a different model version, update the key to include the version string (e.g., `onnx-model-snowflake-arctic-embed-s-v1.5-${{ runner.arch }}`).

**Windows path:** On Windows runners `~` resolves to `C:\Users\runneradmin`. Confirm `ModelManager` uses the same path on Windows or adjust the `path:` value accordingly.

---

## Success Criteria

The workflow is considered complete and passing when:

- All 5 platform × 2 Node version combinations (10 jobs) complete without failures
- T1 through T8 all pass on every platform
- No job is skipped except the Windows shebang check (T3 POSIX variant)
- The workflow runs in under 15 minutes total wall-clock time

---

## Resolved Questions

1. **Keyring bypass flag name** — Resolved: `CHAOSKB_UNSAFE_NO_KEYRING=1`. The name includes "unsafe" to discourage accidental use. When set, `initializeDependencies()` generates an ephemeral master key in memory instead of opening the persisted `@de-otio/keyring` storage (`KeyRing.unlock` → `withMaster`). A loud warning is written to stderr on startup.

2. **MCP server keyring dependency** — Resolved: `mcp-server.ts:initializeDependencies()` calls into the keyring unconditionally on startup. The bypass generates an ephemeral key and also synthesizes a minimal config object so that `loadConfig()` returning null does not cause `process.exit(1)`.

3. **Windows model path** — `ModelManager` uses `os.homedir()` which resolves to `%USERPROFILE%` on Windows. The workflow uses `~/.chaoskb/models` which GitHub Actions expands correctly on all platforms. Confirmed compatible.

4. **ONNX model in CI** — Resolved: The workflow downloads the model via `curl` on cache miss and caches it via `actions/cache` keyed on `runner.arch`. T4 runs full inference when the model is present.

5. **ARM runner availability** — Resolved: `ubuntu-24.04-arm` is a GitHub-hosted runner and is available.
