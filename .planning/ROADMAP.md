# Roadmap: LogBoost Cross-Platform Support

## Overview

LogBoost currently hardcodes Windows path separators throughout its codebase, preventing compilation and execution on Linux. This roadmap delivers cross-platform path handling in three phases: fix the main orchestration paths, fix the helper/enrichment paths, then verify the entire application compiles and runs on Linux via WSL. All work happens on a dedicated git branch.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Core Path Fixes** - Create branch, replace hardcoded separators in main.go (file discovery, output paths)
- [x] **Phase 2: Helper Path Fixes** - Replace hardcoded separators in all helper modules (MaxMind, threat intel, caches)
- [ ] **Phase 3: Build and Verify** - Compile for Linux, run tests, end-to-end verification in WSL

## Phase Details

### Phase 1: Core Path Fixes
**Goal**: LogBoost's main orchestration (file discovery, output path generation) uses platform-agnostic paths
**Depends on**: Nothing (first phase)
**Requirements**: PATH-01, PATH-02, PATH-03, PATH-04
**Success Criteria** (what must be TRUE):
  1. A dedicated git branch exists for cross-platform work, isolating changes from main
  2. All path construction in main.go uses `filepath.Join()` instead of string concatenation with backslashes
  3. `findLogsToProcess()` builds file paths using `filepath.Join()` so directory traversal produces valid paths on any OS
  4. Output file path generation in main.go uses `filepath.Join()` so enriched CSV output lands in the correct location on any OS
**Plans**: 2 plans

Plans:
- [x] 01-01-PLAN.md -- Create feature/cross-platform branch and apply cosmetic path cleanups (help text, dead code)
- [x] 01-02-PLAN.md -- Refactor critical path logic with filepath.Rel() and filepath.Join(), verify build

### Phase 2: Helper Path Fixes
**Goal**: All enrichment helpers (MaxMind, threat intel, DNS/WHOIS/IDB caches) use platform-agnostic paths
**Depends on**: Phase 1
**Requirements**: DBPATH-01, DBPATH-02, DBPATH-03, DBPATH-04
**Success Criteria** (what must be TRUE):
  1. MaxMind database glob patterns and download/extraction paths in helpers/maxmind.go use `filepath.Join()` so databases are discovered and written correctly on Linux
  2. Threat intelligence database path construction in helpers/threatIntel.go uses `filepath.Join()` so `threats.db` operations work on Linux
  3. Cache file paths (`dns.cache`, `whois.cache`, `idb.cache`) in helpers/helpers.go use `filepath.Join()` so caching works on Linux
  4. No hardcoded backslash path separators remain anywhere in the helpers/ directory
**Plans**: 2 plans

Plans:
- [x] 02-01-PLAN.md -- Fix MaxMind and threat intel database paths with filepath.Join
- [x] 02-02-PLAN.md -- Fix helpers.go paths and sweep helpers/ for remaining hardcoded separators

### Phase 3: Build and Verify
**Goal**: LogBoost compiles for Linux and runs end-to-end on a Linux filesystem
**Depends on**: Phase 2
**Requirements**: BUILD-01, BUILD-02, BUILD-03
**Success Criteria** (what must be TRUE):
  1. `GOOS=linux GOARCH=amd64 go build` completes without errors
  2. Existing Go tests pass when run under WSL/Linux
  3. The Linux binary processes a sample log file end-to-end in WSL, producing enriched CSV output in the correct location
**Plans**: 1 plan

Plans:
- [ ] 03-01-PLAN.md -- Cross-compile, verify test parity (Windows vs WSL), and compare end-to-end output

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Core Path Fixes | 2/2 | Complete | 2026-02-06 |
| 2. Helper Path Fixes | 2/2 | Complete | 2026-02-06 |
| 3. Build and Verify | 0/1 | Not started | - |
