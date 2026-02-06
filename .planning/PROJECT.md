# LogBoost Cross-Platform Support

## What This Is

LogBoost is a Go-based log parsing and enrichment CLI tool that reads logs in multiple formats (CEF, CLF, CSV, IIS/W3C, JSON, syslog, KV, raw), enriches them with GeoIP, DNS, threat intel, and WHOIS data, and outputs enriched CSV results. This milestone focuses on making LogBoost compile and run correctly on Linux while preserving Windows support.

## Core Value

LogBoost must handle file paths, directory operations, and OS interactions in a platform-agnostic way so the same codebase compiles and runs correctly on both Windows and Linux.

## Requirements

### Validated

- ✓ Multi-format log parsing (CEF, CLF, CSV, IIS/W3C, JSON, multi-JSON, syslog, KV, raw) — existing
- ✓ IP enrichment via MaxMind GeoLite2 databases (ASN, City, Country) — existing
- ✓ Threat intelligence database build/query from configurable feeds — existing
- ✓ DNS reverse lookup enrichment with caching — existing
- ✓ WHOIS enrichment with caching — existing
- ✓ Concurrent file processing with configurable goroutine limits — existing
- ✓ Structured logging via zerolog — existing
- ✓ CLI argument-driven configuration — existing

### Active

- [ ] Replace all hardcoded Windows path separators (`\`) with `filepath.Join()` / `filepath.Separator`
- [ ] Ensure directory creation and file discovery works on Linux filesystem
- [ ] Ensure MaxMind database download/extraction works on Linux
- [ ] Ensure threat intel database paths work on Linux
- [ ] Ensure log file output paths work on Linux
- [ ] Ensure cache file paths (DNS, WHOIS, IDB) work on Linux
- [ ] Verify compilation on Linux (GOOS=linux)
- [ ] Verify end-to-end run on Linux via WSL

### Out of Scope

- Dockerfile or container configuration — not needed now
- CI/CD pipeline changes — manual WSL testing for now
- Performance improvements — separate effort
- Bug fixes unrelated to cross-platform — separate effort
- New features — this is strictly about platform compatibility

## Context

- Codebase analysis identified hardcoded Windows paths in: `main.go` (lines 233, 239, 252), `helpers/maxmind.go` (line 86), `helpers/threatIntel.go` (lines 171, 263, 427), `helpers/helpers.go` (lines 154, 165)
- Go's `path/filepath` package already handles cross-platform paths — the fix is using it consistently
- The codebase already imports `filepath` in several places but falls back to string concatenation with `\` in others
- TODOs in the code already flag this issue
- Testing will be done via WSL on the developer's machine

## Constraints

- **Language**: Go 1.20+ — existing codebase, no language change
- **Compatibility**: Must continue working on Windows after changes
- **Approach**: Work on a dedicated git branch, merge when verified
- **Testing**: Manual verification via WSL

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Use `filepath.Join()` everywhere | Go stdlib, zero dependencies, handles separators per OS | — Pending |
| Branch-based development | Isolate changes, verify before merging to main | — Pending |
| WSL for Linux verification | Developer has WSL available, no CI needed | — Pending |

---
*Last updated: 2026-02-05 after initialization*
