# Phase 1: Core Path Fixes - Research

**Researched:** 2026-02-06
**Domain:** Go cross-platform file path construction (`path/filepath` package)
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

#### Branch strategy
- Branch name: `feature/cross-platform`
- All cross-platform work happens on this branch
- Commits: one commit per file fixed
- Merge strategy: user will create a Pull Request on GitHub when all phases are complete (no direct merge to main)

#### Path fix approach
- Inline `filepath.Join()` replacements at each call site -- no new helper functions
- Catch all patterns: string concatenation with `\`, `os.PathSeparator` misuse, string Replace calls that assume backslash
- Not just the flagged lines -- full grep of `main.go` for any Windows-specific path patterns

#### Scope of sweep
- Full codebase grep for Windows-specific path patterns (in Phase 1, scoped to `main.go`)
- Focus on path separators only -- not drive letters, Windows APIs, or other OS-specific patterns

#### Testing after fixes
- Run `go build` (Windows) after fixing each file to catch compilation issues immediately
- Linux cross-compilation (`GOOS=linux`) deferred to Phase 3

### Claude's Discretion
- Exact `filepath.Join()` argument structure per call site
- Whether to also clean up surrounding path logic if it's clearly wrong

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope

</user_constraints>

## Summary

This phase targets **5 specific locations** in `main.go` where hardcoded Windows backslash separators are used for path construction. The file already imports `path/filepath` and uses `filepath.Base`, `filepath.Dir`, `filepath.Ext`, and `filepath.WalkDir`, so the import is already present. The changes are mechanical `filepath.Join()` replacements at each call site, with one notable exception: the remainder-path logic at line 233 that uses `strings.SplitN` with a hardcoded backslash separator to compute relative subdirectory paths. This should be replaced with `filepath.Rel()`, which is the idiomatic Go approach and is cross-platform by design.

No new dependencies are needed. The Go standard library `path/filepath` package (already imported) provides everything required. The project uses Go 1.20, and all functions referenced (`filepath.Join`, `filepath.Rel`) have been stable since Go 1.0.

**Primary recommendation:** Replace all 5 backslash-containing path constructions in `main.go` with `filepath.Join()` calls, and replace the `strings.SplitN` relative-path hack at line 233 with `filepath.Rel()` for correct cross-platform behavior.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `path/filepath` (Go stdlib) | Go 1.20+ | Cross-platform path construction | OS-aware separator handling, part of Go stdlib, zero dependencies |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `filepath.Join()` | stable since Go 1.0 | Join path elements with OS separator | Every path concatenation |
| `filepath.Rel()` | stable since Go 1.0 | Compute relative path between two paths | Replacing the `SplitN` hack for remainder paths |
| `filepath.Dir()` | stable since Go 1.0 | Get directory portion of path | Already used in codebase |
| `filepath.Base()` | stable since Go 1.0 | Get filename portion of path | Already used in codebase |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `filepath.Rel()` for remainder path | `strings.TrimPrefix` + `filepath.Join` | `Rel()` is cleaner and handles edge cases (trailing separators, clean paths) automatically |
| `filepath.Join()` | `fmt.Sprintf` with `string(filepath.Separator)` | `Join()` is cleaner, also calls `Clean()` internally |

**Installation:** No installation needed -- `path/filepath` is part of Go stdlib and is already imported in `main.go`.

## Architecture Patterns

### Pattern: filepath.Join for all path construction
**What:** Replace every `fmt.Sprintf("%v\\%v", a, b)` with `filepath.Join(a, b)`
**When to use:** Every time two or more path components need to be concatenated.
**Example:**
```go
// Source: https://pkg.go.dev/path/filepath#Join
// BEFORE (Windows-only):
outputPath = fmt.Sprintf("%v\\%v", outputDir, remainderPath)

// AFTER (cross-platform):
outputPath = filepath.Join(outputDir, remainderPath)
```

### Pattern: filepath.Rel for relative path computation
**What:** Replace `strings.SplitN(dir, prefix+"\\", 2)` with `filepath.Rel(basePath, targetPath)`
**When to use:** When you need the relative portion of a path within a known parent directory.
**Example:**
```go
// Source: https://pkg.go.dev/path/filepath#Rel
// BEFORE (Windows-only, fragile):
remainderPathSplit := strings.SplitN(filepath.Dir(file), fmt.Sprintf("%v\\", arguments["logdir"].(string)), 2)
remainderPath := ""
if len(remainderPathSplit) == 2 {
    remainderPath = remainderPathSplit[1]
}

// AFTER (cross-platform, robust):
relPath, err := filepath.Rel(arguments["logdir"].(string), filepath.Dir(file))
if err != nil {
    // handle error -- fall back to outputDir
}
// relPath is now "subdir" or "subdir/nested" etc., or "." if same directory
```

### Anti-Patterns to Avoid
- **String concatenation with `\\` for paths:** Always use `filepath.Join()`. Backslash is only valid on Windows.
- **`strings.SplitN` with hardcoded separator for relative paths:** Use `filepath.Rel()` which handles separator differences, trailing slashes, and path cleaning automatically.
- **`fmt.Sprintf` for path construction:** Even with `string(filepath.Separator)`, `filepath.Join()` is cleaner because it also calls `filepath.Clean()` internally, eliminating double separators and normalizing paths.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Joining path components | `fmt.Sprintf("%v\\%v", a, b)` | `filepath.Join(a, b)` | Handles OS separator, cleans paths, handles empty elements |
| Getting relative path within parent | `strings.SplitN(path, parent+"\\", 2)` | `filepath.Rel(parent, path)` | Handles all edge cases: trailing slashes, `.` paths, mixed separators |
| Getting OS-appropriate separator | Hardcoded `\\` | `filepath.Separator` or just `filepath.Join()` | Separator differs between Windows (`\`) and Unix (`/`) |

**Key insight:** Go's `path/filepath` package handles all the cross-platform path logic internally. Every hand-rolled path construction using string operations is a potential bug on a different OS.

## Common Pitfalls

### Pitfall 1: filepath.Rel returns "." for same directory
**What goes wrong:** When `filepath.Dir(file)` equals the logdir itself (file is directly in the root input directory, not a subdirectory), `filepath.Rel()` returns `"."`.
**Why it happens:** `"."` is the correct relative path from a directory to itself.
**How to avoid:** After calling `filepath.Rel()`, check if the result is `"."` and handle it -- when the result is `"."`, the output path should just be `outputDir` directly. When using `filepath.Join(outputDir, ".")`, the result is just `outputDir` (since `filepath.Clean` eliminates `.`), so `filepath.Join` actually handles this correctly with no special case needed.
**Warning signs:** Test with files directly in the input directory (no subdirectory).

### Pitfall 2: Forgetting the flag help text backslash
**What goes wrong:** The flag description on line 27 contains `$CWD\\output` which is a cosmetic/documentation issue, not a functional path bug.
**Why it happens:** It's a string literal in a help message, not a path construction.
**How to avoid:** This is a cosmetic choice. The user decided to focus on path separators only. This help text backslash is in a user-facing description string, not in path construction logic. It could be updated for consistency, but it does not affect runtime behavior on any platform.
**Warning signs:** N/A -- non-functional.

### Pitfall 3: The commented-out glob pattern on line 152
**What goes wrong:** Line 152 has a commented-out `fmt.Sprintf("%v\\*.csv", logDir)` glob pattern.
**Why it happens:** Dead code from a previous approach.
**How to avoid:** Since it is commented out, it has no runtime effect. It can be left as-is or cleaned up as a discretionary improvement.
**Warning signs:** N/A -- dead code.

### Pitfall 4: Removing unused imports after changes
**What goes wrong:** After replacing `fmt.Sprintf` calls, the `fmt` import might become unused if no other `fmt` calls remain in the file. Go compilation will fail on unused imports.
**Why it happens:** Go enforces no unused imports.
**How to avoid:** Check that all imports are still used after making changes. In this case, `fmt` is used extensively throughout `main.go` (for `Sprintf`, `Println`, etc.), so it will NOT become unused. The `strings` package is used for `strings.HasSuffix`, `strings.ToLower`, `strings.TrimSuffix`, etc., so it also will NOT become unused. However, if the `SplitN` call is removed and no other `strings.SplitN` calls remain, verify `strings` is still needed (it is -- many other `strings` calls exist).
**Warning signs:** `go build` will immediately flag unused imports.

### Pitfall 5: filepath.Rel error when paths have different roots
**What goes wrong:** `filepath.Rel()` returns an error when the base and target paths cannot be made relative (e.g., different drive letters on Windows, or one absolute and one relative).
**Why it happens:** On Windows, `filepath.Rel("C:\\input", "D:\\input\\file")` cannot produce a relative path.
**How to avoid:** In this codebase, `filepath.WalkDir(logDir, visit)` always produces paths rooted at `logDir`, so the paths will always share the same root. Still, handle the error return from `filepath.Rel()` gracefully by falling back to `outputDir` as the output path.
**Warning signs:** Only manifests when paths span different volume roots, which should not happen with `WalkDir`.

## Code Examples

### Verified transformation patterns for each call site in main.go

#### Call Site 1: Line 27 -- Flag help text (COSMETIC ONLY)
```go
// Current (line 27):
outputDir := flag.String("outputdir", "output", "Directory where enriched output will be stored - defaults to '$CWD\\output'")

// Option A -- leave as-is (it's a help string, not path logic)
// Option B -- update for cross-platform friendliness:
outputDir := flag.String("outputdir", "output", "Directory where enriched output will be stored - defaults to '$CWD/output'")

// RECOMMENDATION: Update to use forward slash since it's descriptive text and
// forward slash is universally understood. Discretionary.
```

#### Call Site 2: Line 233 -- Remainder path computation (CRITICAL)
```go
// Current (line 233-241):
remainderPathSplit := strings.SplitN(filepath.Dir(file), fmt.Sprintf("%v\\", arguments["logdir"].(string)), 2)
remainderPath := ""
outputPath := ""
if len(remainderPathSplit) == 2 {
    remainderPath = remainderPathSplit[1]
    outputPath = fmt.Sprintf("%v\\%v", outputDir, remainderPath)
} else {
    outputPath = outputDir
}

// Replacement (using filepath.Rel):
relDir, relErr := filepath.Rel(arguments["logdir"].(string), filepath.Dir(file))
outputPath := outputDir
if relErr == nil && relDir != "." {
    outputPath = filepath.Join(outputDir, relDir)
}

// NOTE: filepath.Join(outputDir, ".") == outputDir, so the relDir != "."
// check is technically unnecessary. But it makes the intent explicit.
// SIMPLER ALTERNATIVE that works correctly:
relDir, relErr := filepath.Rel(arguments["logdir"].(string), filepath.Dir(file))
if relErr != nil {
    relDir = "."
}
outputPath := filepath.Join(outputDir, relDir)
```

#### Call Site 3: Line 239 -- Output path with remainder (handled by Site 2)
```go
// Current (line 239):
outputPath = fmt.Sprintf("%v\\%v", outputDir, remainderPath)

// This line is eliminated entirely by the filepath.Rel refactor above.
// It becomes:
outputPath = filepath.Join(outputDir, relDir)
```

#### Call Site 4: Line 252 -- Output file path (CRITICAL)
```go
// Current (line 252):
outputFile := fmt.Sprintf("%v\\%v", outputPath, baseFile)

// Replacement:
outputFile := filepath.Join(outputPath, baseFile)
```

#### Call Site 5: Line 152 -- Commented-out glob pattern (DEAD CODE)
```go
// Current (line 152):
//globPattern := fmt.Sprintf("%v\\*.csv", logDir)

// RECOMMENDATION: Leave as-is (commented out, no runtime effect) or delete
// the dead code as discretionary cleanup.
```

### Complete transformed enrichLogs loop section (lines 223-252)
```go
// Source: Go stdlib path/filepath documentation
// https://pkg.go.dev/path/filepath

for _, file := range logFiles {
    base := strings.ToLower(filepath.Base(file))
    if !strings.HasSuffix(base, ".csv") && !arguments["convert"].(bool) && !vars.GetAllFiles {
        continue
    }
    inputFile := file

    // Compute the relative subdirectory path from logdir to the file's directory
    relDir, relErr := filepath.Rel(arguments["logdir"].(string), filepath.Dir(file))
    if relErr != nil {
        relDir = "."
    }
    outputPath := filepath.Join(outputDir, relDir)

    err := os.MkdirAll(outputPath, os.ModePerm)
    if err != nil {
        logger.Error().Msg(err.Error())
        continue
    }

    baseFile := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
    baseFile += ".csv"
    outputFile := filepath.Join(outputPath, baseFile)

    // ... rest of the loop unchanged
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `fmt.Sprintf("%v\\%v", a, b)` | `filepath.Join(a, b)` | Go 1.0 (2012) | `filepath.Join` has been available since Go's inception |
| `strings.SplitN` for relative paths | `filepath.Rel(base, target)` | Go 1.0 (2012) | `filepath.Rel` has been stable since Go 1.0 |

**Deprecated/outdated:**
- The `path` package (not `path/filepath`) uses forward slashes only and is for URL paths, not file system paths. The codebase correctly uses `path/filepath`.

## Open Questions

1. **Flag help text backslash (line 27)**
   - What we know: It is a user-facing description string, not functional path code
   - What's unclear: Whether the user considers this in-scope for "path separators"
   - Recommendation: Update to forward slash as discretionary cleanup (Claude's discretion area allows cleaning up "clearly wrong" surrounding logic)

2. **Commented-out dead code (lines 152-153)**
   - What we know: Two lines of commented-out code with a hardcoded backslash glob pattern
   - What's unclear: Whether to delete or update the dead code
   - Recommendation: Delete the two commented-out lines as discretionary cleanup. They serve no purpose and contain a Windows-specific pattern.

3. **`filepath.Rel` vs simpler `filepath.Join`-only approach for line 233**
   - What we know: `filepath.Rel()` is the idiomatic approach and handles edge cases correctly
   - What's unclear: Whether the user prefers minimal changes (keep the SplitN structure but fix the separator) vs. a cleaner rewrite using `filepath.Rel()`
   - Recommendation: Use `filepath.Rel()` -- it is a direct inline replacement (no new helper function), eliminates 6 lines of fragile logic, and is the standard Go pattern. This falls within Claude's discretion to "clean up surrounding path logic if clearly wrong."

## Sources

### Primary (HIGH confidence)
- Go `path/filepath` official documentation: https://pkg.go.dev/path/filepath -- Verified `filepath.Join`, `filepath.Rel`, `filepath.Dir`, `filepath.Base`, `filepath.Clean` behavior
- Direct codebase analysis of `main.go` (633 lines) -- All 5 backslash occurrences identified and traced

### Secondary (MEDIUM confidence)
- None needed -- this is entirely Go stdlib with stable, well-documented behavior

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- Go stdlib `path/filepath`, stable since Go 1.0, verified via official docs
- Architecture: HIGH -- Direct mechanical replacements with one well-scoped refactor using `filepath.Rel()`
- Pitfalls: HIGH -- Edge cases identified through code tracing, all have clear mitigations

**Research date:** 2026-02-06
**Valid until:** Indefinite (Go stdlib `path/filepath` is frozen and stable)

---

## Appendix: Complete Inventory of Windows-Specific Path Patterns in main.go

| Line | Code | Type | Severity | Fix |
|------|------|------|----------|-----|
| 27 | `"$CWD\\output"` in flag help text | Cosmetic backslash in string literal | LOW | Change `\\` to `/` in help text (discretionary) |
| 152 | `//globPattern := fmt.Sprintf("%v\\*.csv", logDir)` | Dead code (commented out) | NONE | Delete or leave (discretionary) |
| 233 | `strings.SplitN(filepath.Dir(file), fmt.Sprintf("%v\\", arguments["logdir"].(string)), 2)` | Hardcoded `\\` in path split logic | **HIGH** | Replace entire block with `filepath.Rel()` |
| 239 | `fmt.Sprintf("%v\\%v", outputDir, remainderPath)` | Hardcoded `\\` in path join | **HIGH** | Replace with `filepath.Join(outputDir, relDir)` |
| 252 | `fmt.Sprintf("%v\\%v", outputPath, baseFile)` | Hardcoded `\\` in path join | **HIGH** | Replace with `filepath.Join(outputPath, baseFile)` |

**Total changes needed:** 3 HIGH-severity functional fixes (lines 233, 239, 252 -- which collapse into a single refactored block), plus 2 discretionary cosmetic cleanups (lines 27, 152).

**Import changes:** None -- `path/filepath` is already imported.
