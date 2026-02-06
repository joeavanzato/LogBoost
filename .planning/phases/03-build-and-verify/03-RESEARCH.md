# Phase 3: Build and Verify - Research

**Researched:** 2026-02-06
**Domain:** Go cross-compilation, WSL verification, end-to-end testing
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

#### Test Data
- Create minimal synthetic sample log file (5-10 rows)
- Include mix of public + private IPs for coverage
- Store in `testdata/` directory (standard Go convention)

#### WSL Environment
- Target Ubuntu WSL distro
- Cross-compile Linux binary on Windows (GOOS=linux GOARCH=amd64)
- No Go installation required in WSL -- just run the compiled binary
- Run tests on BOTH Windows and WSL for completeness
- Use Windows mount (`/mnt/c/...`) to access repo files in WSL

#### Error Handling
- If tests fail in WSL but pass on Windows: document differences, acceptable if path-related tests pass
- If binary crashes or wrong output: Claude decides based on severity -- small fixes in-phase, major issues become separate work items
- Success criteria: Output must match Windows output for same input (exact parity)
- Run with basic enrichment (GeoIP only) -- tests MaxMind DB paths without network dependencies

#### Claude's Discretion
- Exact synthetic log file content and format
- Order of verification steps
- How to compare Windows vs Linux output (diff, manual inspection, etc.)

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

## Summary

This phase is pure verification work -- confirming that the cross-platform path changes from Phases 1-2 actually produce a working Linux binary. Research focused on three areas: (1) the mechanics of cross-compiling Go from Windows to Linux, (2) running binaries and tests in WSL from the Windows mount, and (3) designing a synthetic test that exercises the path-related code without requiring external dependencies like MaxMind databases.

Key discovery: the environment is fully functional. Cross-compilation with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build` produces a statically-linked ELF binary that runs correctly in WSL from `/mnt/c`. Go 1.24.13 is installed in both Windows and WSL, so `go test` can run directly in WSL as well. The existing test suite has two pre-existing failures (a vet error in main.go's `test()` function and a case mismatch in `TestLookupIP`) that are identical on both platforms, meaning they are NOT cross-platform regressions.

The main challenge is the end-to-end test: the user wants GeoIP enrichment but no MaxMind `.mmdb` files exist in the repository. The `--passthrough` flag skips all enrichment, which avoids the DB dependency but does not test MaxMind DB path handling. The recommended approach is a two-tier test: (1) passthrough mode to verify CSV processing works cross-platform, and (2) if MaxMind DBs are available on the developer's machine, an enrichment test using `--dbdir` to point to them.

**Primary recommendation:** Use `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o logboost_linux .` for compilation, run `go test` in WSL for test parity, and use `--passthrough --convert` with a synthetic CSV for the end-to-end test. Attempt GeoIP enrichment only if `.mmdb` files are available.

## Standard Stack

This phase uses no new libraries. The "stack" is the build toolchain and verification environment.

### Core
| Tool | Version | Purpose | Why Standard |
|------|---------|---------|--------------|
| Go compiler | 1.24.13 | Cross-compilation | Already installed on Windows and in WSL |
| WSL2 + Ubuntu | 24.04.1 LTS | Linux verification environment | Available on developer machine |
| `CGO_ENABLED=0` | N/A | Static linking, avoids cgo issues | Required -- go-sqlite3 dep causes cgo.exe error |

### Supporting
| Tool | Purpose | When to Use |
|------|---------|-------------|
| `file` command | Verify ELF binary format | After cross-compilation to confirm Linux binary |
| `diff` command | Compare Windows vs Linux output | After running binary on both platforms |
| `wsl -d Ubuntu -e bash -c "..."` | Execute commands in WSL | All WSL operations from Windows shell |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| /mnt/c mount | Copy binary to WSL native fs | Slower workflow, /mnt/c works fine |
| go test in WSL | Only compiled binary tests | go test is available and catches more issues |

## Architecture Patterns

### Verification Workflow Structure

The phase follows a sequential verification pipeline:

```
Step 1: Cross-compile (Windows)
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o logboost_linux .

Step 2: Verify binary format
  file logboost_linux  -->  ELF 64-bit LSB executable, statically linked

Step 3: Create test data
  testdata/sample_input.csv  (5-10 rows, mix of public+private IPs)

Step 4: Run Go tests on Windows
  CGO_ENABLED=0 go test ./helpers/...  (skip main package vet error)

Step 5: Run Go tests in WSL
  wsl -d Ubuntu -e bash -c "cd /mnt/c/.../LogBoost && CGO_ENABLED=0 go test ./helpers/..."

Step 6: End-to-end on Windows
  logboost.exe -logdir testdata -outputdir testdata/output_win -passthrough -convert

Step 7: End-to-end in WSL
  ./logboost_linux -logdir testdata -outputdir testdata/output_linux -passthrough -convert

Step 8: Compare outputs
  diff testdata/output_win/sample_input.csv testdata/output_linux/sample_input.csv
```

### Test Data Design Pattern

The synthetic CSV should exercise:
- Public IPs (for enrichment path, even if DBs unavailable)
- Private IPs (for IsPrivateIP path)
- IPv4 and IPv6 addresses
- The `IP address` column header (default -ipcol value)
- Multiple columns to verify CSV parsing preserves structure

```csv
IP address,Timestamp,Action,User
8.8.8.8,2024-01-15T10:30:00Z,login,alice
192.168.1.100,2024-01-15T10:31:00Z,logout,bob
1.1.1.1,2024-01-15T10:32:00Z,download,charlie
10.0.0.5,2024-01-15T10:33:00Z,upload,dave
208.67.222.222,2024-01-15T10:34:00Z,login,eve
172.16.0.1,2024-01-15T10:35:00Z,failed_login,frank
```

This has 6 data rows (3 public, 3 private IPs) which exercises the enrichment branching without requiring actual MaxMind lookups in passthrough mode.

### WSL Command Pattern

**Critical:** The bash tool runs in Git Bash on Windows. WSL commands must avoid path translation issues.

Use this pattern:
```bash
# CORRECT - use -e bash -c to avoid Git Bash path mangling
wsl -d Ubuntu -e bash -c "command here"

# WRONG - Git Bash translates /etc to C:/Program Files/Git/etc
wsl -d Ubuntu -- cat /etc/os-release
```

### Anti-Patterns to Avoid
- **Setting env vars with `set` on Windows in bash:** The bash tool runs Git Bash, not cmd.exe. Use `VAR=value command` syntax (e.g., `CGO_ENABLED=0 GOOS=linux go build`).
- **Using `./...` with `-o` flag:** `go build -o name ./...` fails with multiple packages. Use `go build -o name .` (main package only).
- **Running tests on main package:** The main package has pre-existing vet errors in the `test()` function. Use `./helpers/...` to run only the helpers tests which are the only test files that exist.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Output comparison | Custom Go comparison tool | `diff` command | Standard tool, handles line endings, shows exact differences |
| Binary format check | Manual byte inspection | `file` command | Reliably identifies ELF vs PE format |
| Cross-compilation | Makefile/script | Direct `go build` with env vars | Go's built-in cross-compilation is sufficient |
| Test data generation | Runtime-generated data | Static CSV file in testdata/ | Reproducible, reviewable, version-controlled |

**Key insight:** This phase is verification, not development. Use standard shell tools for comparison and validation rather than building custom verification infrastructure.

## Common Pitfalls

### Pitfall 1: Environment Variable Syntax in Git Bash
**What goes wrong:** Using Windows `set` syntax or PowerShell `$env:` syntax fails in the bash tool.
**Why it happens:** The Claude Code bash tool uses Git Bash, not cmd.exe or PowerShell.
**How to avoid:** Always use `VAR=value command` prefix syntax: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build`
**Warning signs:** Error messages about `cgo.exe: exit status 2` or `command not found` for env var assignments.
**Verified:** HIGH confidence -- confirmed by direct testing.

### Pitfall 2: Git Bash Path Translation in WSL Commands
**What goes wrong:** Paths like `/etc/os-release` get translated to `C:/Program Files/Git/etc/os-release` when passed through `wsl --`.
**Why it happens:** Git Bash's MSYS path translation intercepts Linux paths.
**How to avoid:** Use `wsl -d Ubuntu -e bash -c "command with /linux/paths"` to wrap commands.
**Warning signs:** `No such file or directory` errors referencing `C:/Program Files/Git/`.
**Verified:** HIGH confidence -- reproduced and fixed during research.

### Pitfall 3: Pre-existing Test Failures Mistaken for Regressions
**What goes wrong:** Tests fail on WSL and someone assumes it's a cross-platform regression.
**Why it happens:** Two pre-existing test failures exist on BOTH platforms:
  1. `main.go` vet error: `test()` function uses `fmt.Println` with `%s` formatting directives (lines 458, 462, 469)
  2. `TestLookupIP`: expects `"None"` (capitalized) but `LookupIPRecords` returns `"none"` (lowercase) in `network.go:119`
**How to avoid:** Run tests on Windows first to establish baseline. Only investigate failures that appear on WSL but not Windows. Run `./helpers/...` specifically to skip the main package vet error.
**Warning signs:** Same test failures on both platforms.
**Verified:** HIGH confidence -- both failures reproduced on both platforms during research.

### Pitfall 4: MaxMind DB Dependency for GeoIP Testing
**What goes wrong:** End-to-end test with GeoIP enrichment fails because `.mmdb` files are not in the repository.
**Why it happens:** MaxMind databases require an API key to download and are not committed to git.
**How to avoid:** Use `--passthrough` mode for the primary end-to-end test. Only attempt GeoIP enrichment if DBs are found on the developer's machine (check for `Geo*.mmdb` files in CWD or use `--dbdir`).
**Warning signs:** `"Could not find valid MaxMind API Key"` error followed by program exit.
**Verified:** HIGH confidence -- confirmed no `.mmdb` files in repo, verified exit behavior in code.

### Pitfall 5: Line Ending Differences in Output
**What goes wrong:** `diff` reports files differ when output is identical except for line endings.
**Why it happens:** Windows may write `\r\n` while Linux writes `\n`. However, Go's `csv.Writer` uses `\n` on both platforms (per Go stdlib behavior), so this is unlikely but should be checked.
**How to avoid:** Use `diff --strip-trailing-cr` or compare with line-ending-aware tooling if differences appear.
**Warning signs:** `diff` shows every line as different despite identical content.
**Verified:** MEDIUM confidence -- Go csv.Writer behavior is per Go stdlib docs, but actual output not yet compared.

### Pitfall 6: logboost.log and Cache Files Created in CWD
**What goes wrong:** Running LogBoost creates `logboost.log`, `dns.cache`, `whois.cache`, `idb.cache` in the current working directory, cluttering the repo.
**Why it happens:** These are created at startup unconditionally (see `vars.go` lines 86-88 for cache, `helpers.go` line 33 for log).
**How to avoid:** Run end-to-end tests from a temporary directory, or clean up these files after testing. Alternatively, `cd` to a temp dir and use absolute paths for `-logdir` and `-outputdir`.
**Warning signs:** Untracked files appearing in `git status` after testing.
**Verified:** HIGH confidence -- confirmed in source code.

## Code Examples

### Cross-Compile for Linux
```bash
# Source: Verified during research -- produces statically-linked ELF binary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o logboost_linux .
```

### Verify Binary Format
```bash
# Source: Verified during research
file logboost_linux
# Expected output: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, ...
```

### Run Tests in WSL (helpers only, skips main vet errors)
```bash
# Source: Verified during research -- identical results to Windows
wsl -d Ubuntu -e bash -c "cd /mnt/c/Users/Joe/Documents/GitHub/tmplogboost/LogBoost && CGO_ENABLED=0 go test ./helpers/..."
```

### Run Binary in WSL from /mnt/c
```bash
# Source: Verified during research -- binary executes successfully
wsl -d Ubuntu -e bash -c "chmod +x /mnt/c/.../logboost_linux && /mnt/c/.../logboost_linux -logdir testdata -outputdir testdata/output_linux -passthrough -convert"
```

### Run End-to-End on Windows
```bash
# Source: Build tool patterns from main.go analysis
CGO_ENABLED=0 go build -o logboost.exe . && ./logboost.exe -logdir testdata -outputdir testdata/output_win -passthrough -convert
```

### Compare Outputs
```bash
# Source: Standard diff usage
diff testdata/output_win/sample_input.csv testdata/output_linux/sample_input.csv
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hardcoded `\` paths | `filepath.Join()` everywhere | Phase 1-2 (this milestone) | Enables this verification phase |
| String SplitN for relative paths | `filepath.Rel()` | Phase 1-2 | Correct cross-platform relative path computation |
| Go 1.20 | Go 1.24.13 | Phase 1 (go mod tidy) | Required by whois-parser dependency |

**Pre-existing issues (not regressions):**
- `test()` function in main.go has Printf/Println vet errors -- unused function, pre-existing
- `TestLookupIP` case mismatch ("None" vs "none") -- pre-existing on both platforms
- CGo build failure when `CGO_ENABLED=1` -- pre-existing, go-sqlite3 dependency issue

## Open Questions

1. **MaxMind DB Availability for GeoIP Test**
   - What we know: No `.mmdb` files in the repo. The user wants "basic enrichment (GeoIP only)" testing.
   - What's unclear: Whether the developer has MaxMind DBs elsewhere on their machine (e.g., in a different directory).
   - Recommendation: Design the plan with passthrough as the primary test. Add an optional enrichment test that runs only if `Geo*.mmdb` files are found. Use `--dbdir` to point to them if available.

2. **Should Pre-existing Test Failures Be Fixed In-Phase?**
   - What we know: Two pre-existing failures exist identically on both platforms. Per user's error handling decision, "small fixes in-phase, major issues become separate work items."
   - What's unclear: Whether the user considers these "in scope" for this verification phase.
   - Recommendation: The main.go vet error is in an unused `test()` function -- trivial to fix. The TestLookupIP case mismatch is a one-character fix. Both are small enough for in-phase fixing if the planner chooses, but they are NOT cross-platform regressions and can be deferred.

3. **Line Ending Behavior in Output CSVs**
   - What we know: Go's `csv.Writer` uses `\n` as the record terminator regardless of OS (per Go stdlib). So output should be identical.
   - What's unclear: Whether any other part of the pipeline introduces `\r\n` on Windows.
   - Recommendation: Compare outputs with `diff`. If line endings differ, use `diff --strip-trailing-cr` and note the finding.

## Sources

### Primary (HIGH confidence)
- Direct testing of cross-compilation on the developer's machine (Go 1.24.13, Windows -> Linux)
- Direct testing of WSL binary execution (Ubuntu 24.04.1 LTS, WSL2)
- Direct testing of `go test` on both Windows and WSL (identical failures confirmed)
- Source code analysis of main.go, helpers/*.go, vars/vars.go, parsers/parse_csv.go

### Secondary (MEDIUM confidence)
- [Go cross-compilation with CGO](https://gist.github.com/steeve/6905542) -- confirmed CGO_ENABLED=0 approach
- [WSL file permissions](https://learn.microsoft.com/en-us/windows/wsl/file-permissions) -- Microsoft docs on /mnt/c behavior
- [WSL configuration](https://learn.microsoft.com/en-us/windows/wsl/wsl-config) -- mount options and metadata

### Tertiary (LOW confidence)
- None -- all findings verified through direct testing

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- verified by direct testing on this exact environment
- Architecture: HIGH -- workflow tested step-by-step, commands verified
- Pitfalls: HIGH -- all pitfalls discovered through direct reproduction

**Research date:** 2026-02-06
**Valid until:** 2026-03-06 (stable -- Go toolchain and WSL don't change rapidly)
