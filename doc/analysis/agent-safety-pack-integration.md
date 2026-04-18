# agent-safety-pack Integration

`@de-otio/agent-safety-pack` is a TypeScript library that provides deterministic safety checks for AI coding agents — URL blocklisting, threat feed lookups, prompt injection detection, and secrets scanning. ChaosKB has independent, partial implementations of two of those things: SSRF protection in `src/pipeline/fetch.ts` and prompt injection detection in `src/pipeline/validate.ts`. When agent-safety-pack is ready, ChaosKB should use it instead.

This document covers what to replace, what to add, how the integration works mechanically, and what it doesn't solve.

## Relevant Attack Surface

`kb_ingest` is ChaosKB's primary attack surface for URL-based threats. It fetches arbitrary user-provided URLs, extracts their content, and stores the result in the local knowledge base. That stored content is later returned to the AI agent via `kb_query`. Every piece of untrusted content that enters the KB starts with `kb_ingest`.

The threat chain has two stages:

```
[User provides URL] → kb_ingest → [fetch] → [extract] → [store in SQLite]
                                                                ↓
                               [AI agent receives content] ← kb_query
```

An attacker who can influence what a URL serves controls what the agent reads. A successful prompt injection at ingest time gets stored in the KB and can surface again on any future query — it is persistent, not just one-session.

The secondary surface is file ingestion. `kb_ingest` also accepts local files (PDF, DOCX, PPTX). These are lower risk — the user already has the file on their machine — but injected content in a document is the same threat as injected content from a URL.

`kb_query` itself has no external input beyond the search query. The threat there is content already stored from a prior ingest, not new untrusted input.

## What ChaosKB Has Today

### SSRF protection (`src/pipeline/fetch.ts:80–170`)

Custom implementation that:
- Rejects non-HTTP(S) schemes
- Resolves DNS and rejects private/RFC 1918 IP ranges, link-local (`169.254.x.x`), IPv6 loopback, ULA, IPv4-mapped IPv6
- Blocks a small set of well-known cloud metadata hostnames (`metadata.google.internal`)

**Coverage:** Good SSRF coverage. Does not cover malware domains, phishing URLs, URL shorteners, paste sites, or request catchers. No threat feed integration.

### Prompt injection detection (`src/pipeline/validate.ts:279–306`)

15 hardcoded regex patterns covering:
- Instruction override phrases ("ignore previous instructions", "disregard", "forget", "override")
- System/role impersonation ("you are now a new AI", "your new role is")
- Delimiter/framing escape (`</system>`, `[/INST]`, `[INST]`, `<<SYS>>`)
- Meta-instruction patterns ("important system update", "do not reveal these instructions")

**Coverage:** Thin. Misses role manipulation, social engineering, hidden text, encoded payloads, and many common override phrasings. The agent-safety-pack `injection-patterns.txt` has ~100 patterns across six threat categories.

### What ChaosKB has that agent-safety-pack replaces

| Current implementation | File | Lines | Replace with |
|------------------------|------|-------|-------------|
| SSRF protection | `src/pipeline/fetch.ts` | 80–170 | `checker.checkUrl()` |
| `PROMPT_INJECTION_PATTERNS` | `src/pipeline/validate.ts` | 279–306 | `checker.checkContentInjection()` |
| `checkPromptInjection()` | `src/pipeline/validate.ts` | 727–756 | `checker.checkContentInjection()` |

The SSRF protection in `fetch.ts` does work the agent-safety-pack also covers. Both check DNS-resolved IPs against private ranges. The difference is that the safety pack adds domain blocklist categories (URL shorteners, paste sites, request catchers) and optional threat feed lookups that the current code has no equivalent of.

## What to Integrate

Four integration points, ranked by value:

### 1. Pre-fetch URL check (highest value)

**Where:** `src/pipeline/content-pipeline.ts`, before `fetchUrl()` is called.

**What it adds:** Three-tier URL check — static domain blocklist, local threat feeds (URLhaus, PhishTank, OpenPhish), optional remote APIs. Covers malware delivery, phishing, and redirect-chain bypass that the current SSRF-only check misses entirely.

**What it replaces:** Nothing directly — this is additive on top of the existing SSRF check. The SSRF check in `fetch.ts` can remain as a defense-in-depth layer; the safety pack check fires before the fetch happens, the SSRF check fires after DNS resolution inside the fetch.

```typescript
const checker = createSafetyChecker({ localFeeds: true });

// Before fetchUrl():
const urlCheck = await checker.checkUrl(url);
if (urlCheck.decision === 'deny') {
  throw new Error(`URL blocked: ${urlCheck.reason}`);
}
// 'ask' can be treated as deny for kb_ingest — there is no human to prompt
```

`kb_ingest` is called by an AI agent, not directly by the user, so treating `ask` as `deny` is correct. There is no interactive override available in the MCP tool context.

### 2. Post-fetch injection scan (replaces existing)

**Where:** `src/pipeline/validate.ts`, `checkPromptInjection()` function.

**What it adds:** ~100 patterns across instruction overrides, role manipulation, delimiter injection, social engineering, hidden text, encoded payloads. Replaces the current 15 patterns.

**What it replaces:** `PROMPT_INJECTION_PATTERNS` (line 279–306) and `checkPromptInjection()` (line 727–756) are deleted. `validateContent()` and `validateFileContent()` call `checker.checkContentInjection()` instead.

```typescript
const check = checker.checkContentInjection(text);
if (check.decision !== 'allow') {
  issues.push({
    severity: 'error',
    code: 'prompt-injection',
    message: check.reason,
  });
}
```

The `ContentIssue` type and the `issues` array pattern already exist — this is a drop-in replacement.

### 3. Post-query injection scan (defense-in-depth)

**Where:** `src/cli/tools/kb-query.ts` or `src/cli/mcp-server.ts`, before the query result is returned to the agent.

**What it adds:** A second injection check at retrieval time. Content was scanned at ingest time, but running the check again on retrieved chunks before returning them catches anything the ingest-time scanner missed (e.g., a pattern added to the library after the content was stored, or content ingested before the library was integrated).

ChaosKB's `wrapQueryResponse()` in `mcp-server.ts` already wraps query results with an untrusted-data framing header. This scan sits alongside that — framing tells the model to treat results as untrusted; the scan blocks actively injected content from reaching the model at all.

**Cost:** Low. `checkContentInjection()` is synchronous, regex-only, takes microseconds per chunk.

### 4. Secrets scan on ingest (optional)

**Where:** `src/pipeline/validate.ts`, added as a Tier 3 check in `validateContent()` and `validateFileContent()`.

**What it adds:** `checker.checkContentSecrets()` flags credentials accidentally present in ingested content — API keys, JWT tokens, PEM private keys, connection strings. This prevents the KB from becoming a credentials store that the AI agent can query.

**When it matters:** A user ingests a GitHub Gist or internal wiki page that happens to contain a key. The key ends up in the KB, and a future query surfaces it to the agent. The scan at ingest time blocks storage of that chunk or surfaces a warning.

**What to do with a match:** Probably a warning-severity issue, not an error. Store the content, but log a warning that the ingested document contained what looks like a secret. The user may have intentionally ingested it; blocking is too aggressive.

## Integration Points Summary

| Integration | Where | Decision handling | Replaces / Adds |
|-------------|-------|-------------------|-----------------|
| Pre-fetch URL check | `content-pipeline.ts` | `deny` → throw; `ask` → throw (no user to prompt) | Adds: malware/phishing/blocklist coverage |
| Post-fetch injection scan | `validate.ts` `checkPromptInjection()` | `deny`/`ask` → `error`-severity `ContentIssue` | Replaces: 15 hardcoded patterns with ~100 |
| Post-query injection scan | `mcp-server.ts` or `kb-query.ts` | `deny`/`ask` → omit chunk from response | Adds: retrieval-time defense-in-depth |
| Secrets scan on ingest | `validate.ts` Tier 3 | `deny`/`ask` → `warning`-severity `ContentIssue` | Adds: credential contamination detection |

## What Does Not Need Integration

`checkCommand()` and `checkPath()` are not relevant. ChaosKB does not execute shell commands or read arbitrary file paths as part of MCP tool logic. Those checks are for agent environments where the AI drives Bash and file write operations.

The Claude Code hook scripts in agent-safety-pack (`hooks/pre-bash.js`, `hooks/post-write.js`, etc.) are also not a ChaosKB concern. They protect the Claude Code session generally. Installing them alongside ChaosKB is complementary but independent — the MCP tool integration is the integration that belongs in this codebase.

## Dependency and Import

Both packages are under the `@de-otio/` npm scope. Add as a runtime dependency:

```json
{
  "dependencies": {
    "@de-otio/agent-safety-pack": "^1.0.0"
  }
}
```

Create the checker once at startup and pass it into the pipeline:

```typescript
import { createSafetyChecker } from '@de-otio/agent-safety-pack';

const checker = createSafetyChecker({ localFeeds: true });
```

`createSafetyChecker` is synchronous. Feed loading (URLhaus, PhishTank, OpenPhish) happens on construction if `localFeeds: true`. The checker instance is cheap to hold for the lifetime of the MCP server process.

The `validate.ts` functions that currently take `(html, extracted)` do not need to take the checker as a parameter — it can be a module-level singleton or passed through `PipelineConfig`. The cleaner option is `PipelineConfig`: add a `safetyChecker` field, default to a checker initialized with the package defaults, and let tests override it.

## Strict Mode Consideration

agent-safety-pack supports `AGENT_SAFETY_MODE=strict`, which converts `ask` decisions to hard `deny`. For `kb_ingest`, strict mode is the right behavior regardless — there is no human in the loop at tool-call time. Rather than relying on the env var, the integration code should just treat `ask` the same as `deny` explicitly:

```typescript
if (urlCheck.decision !== 'allow') {
  throw new Error(`URL blocked: ${urlCheck.reason}`);
}
```

This is clearer than relying on `AGENT_SAFETY_MODE` and avoids making the behavior depend on an env var that a user might not know to set.

## What This Does Not Solve

| Gap | Why |
|-----|-----|
| Content already stored before integration | The KB may have pre-existing stored content that was never scanned with the safety pack's patterns. A one-time migration scan of stored chunks is the solution; this integration does not do that automatically. |
| Redirect chain bypass | `checkUrl()` checks the URL before the fetch. If the page redirects to a blocked domain, the safety pack does not see the final destination. Resolution: check the final URL after redirect in `fetchUrl()` as well, or configure the HTTP client to not follow redirects automatically and handle them manually. |
| Content-type confusion | An attacker serving `application/octet-stream` when HTML is expected bypasses Readability extraction and may reach the chunks as raw bytes. `fetch.ts` already enforces content-type; the integration does not change this. |
| Injection in chunked content | Injection scanning runs on the full extracted text. A long document where the injection spans a chunk boundary may not match. This is a general limitation of fixed-window scanning; it applies to both the current implementation and the safety pack. |
| Novel injection patterns | The ~100-pattern database is comprehensive for known techniques but cannot catch novel ones. The LLM-based hook layer in agent-safety-pack addresses this at the Claude Code session level, not inside the MCP server itself. |

## Relationship to Existing Threat Model

The existing threat model (`doc/design/threat-model.md`) does not cover prompt injection from ingested content or malicious URLs. Adding this integration effectively extends the threat model with two new rows:

| Threat | Protected after integration? | How |
|--------|------------------------------|-----|
| Malicious URL injects prompt via `kb_ingest` | Yes | Pre-fetch URL check + post-fetch injection scan |
| Phishing/malware URL ingested to KB | Yes | Pre-fetch URL check (threat feeds + blocklist) |
| Credential leakage via ingested documents | Partial | Secrets scan warns; does not block storage |
| Pre-existing stored injection content | No | Requires separate migration scan |
