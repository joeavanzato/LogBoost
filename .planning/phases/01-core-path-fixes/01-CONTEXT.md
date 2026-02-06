# Phase 1: Core Path Fixes - Context

**Gathered:** 2026-02-05
**Status:** Ready for planning

<domain>
## Phase Boundary

Create a `feature/cross-platform` branch and replace all hardcoded Windows path separators in `main.go` with platform-agnostic `filepath.Join()` calls. This phase covers file discovery, output path generation, and any other path construction in `main.go`. Helper files (`helpers/`, `parsers/`) are Phase 2.

</domain>

<decisions>
## Implementation Decisions

### Branch strategy
- Branch name: `feature/cross-platform`
- All cross-platform work happens on this branch
- Commits: one commit per file fixed
- Merge strategy: user will create a Pull Request on GitHub when all phases are complete (no direct merge to main)

### Path fix approach
- Inline `filepath.Join()` replacements at each call site — no new helper functions
- Catch all patterns: string concatenation with `\`, `os.PathSeparator` misuse, string Replace calls that assume backslash
- Not just the flagged lines — full grep of `main.go` for any Windows-specific path patterns

### Scope of sweep
- Full codebase grep for Windows-specific path patterns (in Phase 1, scoped to `main.go`)
- Focus on path separators only — not drive letters, Windows APIs, or other OS-specific patterns

### Testing after fixes
- Run `go build` (Windows) after fixing each file to catch compilation issues immediately
- Linux cross-compilation (`GOOS=linux`) deferred to Phase 3

### Claude's Discretion
- Exact `filepath.Join()` argument structure per call site
- Whether to also clean up surrounding path logic if it's clearly wrong

</decisions>

<specifics>
## Specific Ideas

No specific requirements — standard Go cross-platform path handling with `filepath.Join()`.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 01-core-path-fixes*
*Context gathered: 2026-02-05*
