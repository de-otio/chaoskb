# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.11] - 2026-04-25

### Changed
- Bumped `@de-otio/crypto-envelope` from `^0.3.0-alpha.1` to `^0.3.0` (now released).
- Bumped `@de-otio/keyring` from `^0.1.0-alpha.1` to `^0.2.2` (now released). The new keyring declares a peer on `crypto-envelope ^0.3.0`, so the two packages are now version-aligned. No behavioural changes — wire format and APIs are unchanged.

## [0.3.10] - 2026-04-25

### Changed
- Bumped `@de-otio/crypto-envelope` to `^0.3.0-alpha.1`. Wire format is byte-identical to 0.2.x — every existing on-disk envelope decrypts unchanged. Upstream additions: genuine browser/WebCrypto-only portability (no `Buffer` dep), typed error taxonomy (`AuthenticationFailedError`, `MalformedEnvelopeError`, `UnsupportedAlgorithmError`, `UnsupportedVersionError`, `TruncatedCiphertextError`), and `MessageCounter` integration on `rewrapEnvelope` (optional 4th arg).
- **Partitioning-oracle defense:** wrong CEK, wrong commit key, tampered ciphertext, tampered AAD, and tampered commitment now all surface as the same `AuthenticationFailedError` with a single byte-identical message (`"authentication failed; envelope is wrong key or tampered"`). Decrypt no longer leaks which check failed. chaoskb's commitment-mismatch tests updated to match.

## [0.3.9] - 2026-04-21

### Changed
- Refreshed bundled `guide-hashes.json` to match the updated agent guides at chaoskb.com (security guide gained a "Content safety (ingest-time)" walk-through; troubleshooting guide gained rows for the new ingest-time error codes; install guide post-install step now offers a safety-config walkthrough). No code changes.

## [0.3.8] - 2026-04-20

### Security
- **Prompt-injection detection now blocks ingestion.** Content that matches the safety pack's injection patterns (instruction overrides, role impersonation, delimiter escapes) is no longer silently stored with an advisory warning — `kb_ingest` rejects the page with an error, honouring the `deny` verdict that `@de-otio/agent-safety-pack` was already returning. Secrets detection remains a warning by default (ingesting a page *about* credentials is often legitimate).

### Added
- **Configurable safety policy.** The safety checker is no longer hardcoded; users can tune it via a new `safety` section in `~/.chaoskb/config.json` or the `chaoskb-mcp config safety` CLI subcommand. Exposed dials:
  - `strict` — promote the pack's `'ask'` decisions to `'deny'`.
  - `remoteApis.urlhaus` — enable free URLhaus URL threat-intel (no API key).
  - `remoteApis.googleSafeBrowsing` — Google Safe Browsing v4 (API key).
  - `remoteApis.spamhausDbl` — Spamhaus DBL via DNS.
  - `remoteTimeoutMs` — per-call timeout for remote lookups (default 5000 ms).
  - `injectionPolicy: 'block' | 'warn' | 'allow'` — default `block`.
  - `secretsPolicy: 'block' | 'warn' | 'allow'` — default `warn`.
  Environment variables (`AGENT_SAFETY_URLHAUS`, `AGENT_SAFETY_GSB_KEY`, etc.) continue to work as a lower-precedence fallback. Run `chaoskb-mcp config safety --help` for the full CLI surface.

## [0.3.7] - 2026-04-20

### Added
- **JS-rendered page fallback.** `kb_ingest` now transparently renders client-side SPAs (React, Vue, Angular, Next.js, etc.) via a headless Chromium instance instead of returning "no extractable content". Playwright Library is bundled as a regular dependency; Chromium downloads during `npm install`. The browser is launched lazily on the first JS-rendered URL, reused across sequential ingestions, and self-closes after 60 s idle.
- Typed `JsRenderRequiredError` in `src/pipeline/extract.ts` replaces the ad-hoc string-only throws from the two SPA-detection sites. `content-pipeline.ts::fetchAndExtract` catches it and invokes `fetchUrlWithBrowser`.
- `fetchUrlWithBrowser(url)` in `src/pipeline/fetch-browser.ts`: re-runs SSRF validation before launching Chromium, uses `networkidle` with a `domcontentloaded` fallback, enforces the existing 10 MB size cap on rendered HTML, and closes each `BrowserContext` in `finally` so cookies/cache don't leak between calls.

### Security
- SSRF protections (scheme, blocklist, DNS→private-IP) re-run before every Playwright navigation — the headless browser does not bypass `validateUrl`.

### Changed
- **Crypto primitives extracted to `@de-otio/crypto-envelope`.** chaoskb's in-tree crypto module now re-exports AEAD, HKDF, Argon2id, commitment, canonical JSON, SecureBuffer, AAD construction, blob-ID generation, envelope v1/v2 serialisation, and the high-level `encryptPayload`/`decryptEnvelope` flow from the new package. Internal chaoskb API is unchanged (same `encryptPayload(payload, keys, kid)` signature, same `DerivedKeySet` composition with `chaoskb-content` / `chaoskb-metadata` / `chaoskb-embedding` / `chaoskb-commit` HKDF info strings), so every existing on-disk envelope decrypts byte-identically. Full 223-test suite passes unchanged.
- **Keyring extracted to `@de-otio/keyring`.** In-house keyring duplicates removed; chaoskb now consumes the standalone package for OS keychain access. No behavioural change for users.
- New runtime dependencies: `@de-otio/crypto-envelope@^0.2.0-alpha.1`, `@de-otio/keyring@^0.1.0-alpha.1`.

### Fixed
- Test: PDF extraction timeout actually raised to 30 s on all platforms (previous bump didn't apply everywhere).

## [0.3.6] - 2026-04-12

### Fixed
- CI: removed unused `MAX_RESPONSE_BYTES` import in `fetch.test.ts` (ESLint error)
- CI: Windows path assertion in `file-extract.test.ts` now uses `path.isAbsolute()` instead of a Unix-only regex
- CI: PDF extraction test timeout raised to 30 s on all platforms
- Publish: skip broken v0.3.5 tag (workflow had switched from OIDC to missing `NPM_TOKEN` secret); OIDC trusted publishing restored

## [0.3.5] - 2026-04-11

### Added
- URL blocklist check via `@de-otio/agent-safety-pack` — known malicious URLs are blocked before fetch
- Prompt-injection detection on ingested content (`possible-prompt-injection` warning)
- Secrets scanning on ingested content (`possible-credentials` warning)

## [0.3.4] - 2026-04-10

### Added
- File format ingestion: DOCX, PPTX, and PDF parsing support
- Prompt injection defenses with CSS-hidden element stripping
- SPA page detection for content that requires JS rendering
- Content validation module (soft-404s, paywalls, WAF blocks, login walls, maintenance pages)

### Fixed
- CI build: inline `dns.LookupAddress` type for Node 22 compat, use public `PDFParse` API

## [0.3.3] - 2026-04-07

### Fixed
- MCP server mode not starting with `--project` flag
- CDK construct test timeouts on slow CI runners
- E2E: replace retired `macos-13` runner, fix Windows pack-install
- E2E MCP startup test: remove spurious arg, update tool list
- Windows Node 20 CI: fallback to DER key creation when sshpk PKCS8 fails
- Node 20 test failures: use `ssh-keygen` instead of `generateKeyPairSync`
- Publish workflow: pin `npm@11.12.1`, normalize repo URLs

## [0.3.2] - 2026-04-07

### Fixed
- Sync sequence counter drift with replay recovery

## [0.3.1] - 2026-04-06

### Added
- SQLite-backed sync infrastructure and queue processor
- Sync upload/delete wired into MCP tools with body hash and 409 handling

### Fixed
- Node 25 ESM compatibility and silent init failures
- Sequence counter: use persisted `SequenceCounter` everywhere

## [0.3.0] - 2026-04-06

### Changed
- Replace hand-rolled SSH key parser with `sshpk` library, full key type support

## [0.2.14] - 2026-04-06

### Added
- RSA and ECDSA key support for sync registration

### Fixed
- Sync registration: use challenge-response flow

## [0.2.13] - 2026-04-05

### Fixed
- Backward compatibility for raw 32-byte Ed25519 public keys

## [0.2.12] - 2026-04-05

### Added
- RSA and ECDSA SSH key support for signature signing and verification

## [0.2.11] - 2026-04-05

### Fixed
- Slow MCP handshake: lazy-init deps, improve startup messages

## [0.2.10] - 2026-04-05

### Fixed
- Use `INIT_CWD` for workspace detection during npm postinstall

## [0.2.9] - 2026-04-05

### Added
- Auto-register in workspace `.mcp.json` for VS Code extension
- Show agent registrations and next steps in status before first launch

## [0.2.8] - 2026-04-05

### Changed
- Show post-install message on stdout with activation instructions

## [0.2.7] - 2026-04-05

### Fixed
- Path validator: allow `~/.claude/` directory for Claude Code settings

## [0.2.6] - 2026-04-05

### Fixed
- Claude Code agent detection: correct install paths and config path

## [0.2.5] - 2026-04-05

### Added
- Auto-register with MCP agents on `npm install`

## [0.2.4] - 2026-04-05

### Fixed
- CLI: handle `--version` and `--help` flags in non-TTY mode

## [0.2.3] - 2026-04-05

### Fixed
- CLI hang in non-TTY environments (agent terminals, CI, piped shells)

## [0.2.2] - 2026-04-05

### Fixed
- Link code expiry: use `expiresAtISO` for app-level checks
- Publish workflow: use `npx npm@11` for OIDC trusted publishing

## [0.2.1] - 2026-04-05

### Added
- MCP tools for device management, key rotation, audit, and revocation
- GitHub integration: enumeration mitigations, `--github` CLI, multi-KB support
- `--dry-run` for destructive commands, guide hashes, device metadata

### Changed
- Rename npm scope from `deotio` to `de-otio`

### Fixed
- Rotation auth and DELETE device path routing
- TTL attribute alignment to `expiresAt` across sync server and CDK
- Security hardening: constant-time comparisons, key material zeroing, HKDF domain separation

## [0.2.0] - 2026-03-31

### Added
- Zero-config sync: SSH key identity, replay protection, device linking, sharing

## [0.1.7] - 2026-03-30

### Added
- Maximum-tier unlock with round-trip verification

## [0.1.6] - 2026-03-30

### Added
- Auto-bootstrap, config `upgrade-tier`, simplified setup

## [0.1.5] - 2026-03-28

### Added
- Interactive register, help, and uninstall commands

## [0.1.4] - 2026-03-28

### Changed
- Upgrade Lambda runtimes from Node.js 20 to 22
- Exhaustive e2e platform testing across 5 OS/arch combos

### Fixed
- `registry.json` missing from dist

## [0.1.3] - 2026-03-27

### Added
- Optional `reservedConcurrency` prop to AdminApi construct

## [0.1.2] - 2026-03-27

### Changed
- Switch npm publish to OIDC provenance

## [0.1.1] - 2026-03-27

_Patch release — no user-facing changes._

## [0.1.0] - 2026-03-27

### Added
- Initial release: encrypted knowledge base with MCP integration
- Full-text search with FTS5, CBOR serialization, sync conflict resolution
- Tokenizer, encrypted import/export, SSH agent support
- CDK construct library for hosted backend

[0.3.4]: https://github.com/de-otio/chaoskb/releases/tag/v0.3.4
[0.3.3]: https://github.com/de-otio/chaoskb/releases/tag/v0.3.3
[0.3.2]: https://github.com/de-otio/chaoskb/releases/tag/v0.3.2
[0.3.1]: https://github.com/de-otio/chaoskb/releases/tag/v0.3.1
[0.3.0]: https://github.com/de-otio/chaoskb/releases/tag/v0.3.0
[0.2.14]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.14
[0.2.13]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.13
[0.2.12]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.12
[0.2.11]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.11
[0.2.10]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.10
[0.2.9]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.9
[0.2.8]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.8
[0.2.7]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.7
[0.2.6]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.6
[0.2.5]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.5
[0.2.4]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.4
[0.2.3]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.3
[0.2.2]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.2
[0.2.1]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.1
[0.2.0]: https://github.com/de-otio/chaoskb/releases/tag/v0.2.0
[0.1.7]: https://github.com/de-otio/chaoskb/releases/tag/v0.1.7
[0.1.6]: https://github.com/de-otio/chaoskb/releases/tag/v0.1.6
[0.1.5]: https://github.com/de-otio/chaoskb/releases/tag/v0.1.5
[0.1.4]: https://github.com/de-otio/chaoskb/releases/tag/v0.1.4
[0.1.3]: https://github.com/de-otio/chaoskb/releases/tag/v0.1.3
[0.1.2]: https://github.com/de-otio/chaoskb/releases/tag/v0.1.2
[0.1.1]: https://github.com/de-otio/chaoskb/releases/tag/v0.1.1
[0.1.0]: https://github.com/de-otio/chaoskb/releases/tag/v0.1.0
