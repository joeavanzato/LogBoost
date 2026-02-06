# Phase 3: Build and Verify - Context

**Gathered:** 2026-02-06
**Status:** Ready for planning

<domain>
## Phase Boundary

Verify that LogBoost compiles for Linux and runs correctly on a Linux filesystem via WSL. This is verification work only — confirming Phases 1-2 actually work on Linux. No new code features.

</domain>

<decisions>
## Implementation Decisions

### Test Data
- Create minimal synthetic sample log file (5-10 rows)
- Include mix of public + private IPs for coverage
- Store in `testdata/` directory (standard Go convention)

### WSL Environment
- Target Ubuntu WSL distro
- Cross-compile Linux binary on Windows (GOOS=linux GOARCH=amd64)
- No Go installation required in WSL — just run the compiled binary
- Run tests on BOTH Windows and WSL for completeness
- Use Windows mount (`/mnt/c/...`) to access repo files in WSL

### Error Handling
- If tests fail in WSL but pass on Windows: document differences, acceptable if path-related tests pass
- If binary crashes or wrong output: Claude decides based on severity — small fixes in-phase, major issues become separate work items
- Success criteria: Output must match Windows output for same input (exact parity)
- Run with basic enrichment (GeoIP only) — tests MaxMind DB paths without network dependencies

### Claude's Discretion
- Exact synthetic log file content and format
- Order of verification steps
- How to compare Windows vs Linux output (diff, manual inspection, etc.)

</decisions>

<specifics>
## Specific Ideas

- CGO_ENABLED=0 required for build (pre-existing constraint from Phase 1/2)
- GeoIP enrichment needs MaxMind DBs — may need to skip if not available in test environment

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 03-build-and-verify*
*Context gathered: 2026-02-06*
