# Testing Patterns

**Analysis Date:** 2026-02-05

## Test Framework

**Runner:**
- Go built-in `testing` package (Go 1.20)
- No explicit test runner configuration file present
- Tests executed via standard `go test` command

**Assertion Library:**
- Go's built-in testing with manual assertions
- No external assertion library in use

**Run Commands:**
```bash
go test ./...              # Run all tests
go test -v ./...           # Run all tests with verbose output
go test -run TestName      # Run specific test
go test -cover ./...       # Check coverage
```

## Test File Organization

**Location:**
- Co-located with source code in same package
- Example: `C:/Users/Joe/Documents/GitHub/tmplogboost/LogBoost/helpers/network_test.go` in `helpers/` package

**Naming:**
- File suffix: `_test.go`
- Test function prefix: `Test`
- Example: `TestSetupPrivateNetworks()`, `TestIsPrivateIP()`, `TestLookupIP()`

**Structure:**
```
helpers/
├── helpers.go
├── network.go
├── network_test.go      # Tests for network.go
├── maxmind.go
├── threatIntel.go
├── whois.go
└── ipNetGen.go
```

## Test Structure

**Suite Organization:**

From `C:/Users/Joe/Documents/GitHub/tmplogboost/LogBoost/helpers/network_test.go`:

```go
func TestSetupPrivateNetworks(t *testing.T) {
	want := 12
	err := SetupPrivateNetworks()
	if err != nil {
		t.Fatalf(`Error setupPrivateNetworks: %v`, err)
	}
	if len(PrivateIPBlocks) != want {
		t.Fatalf(`Error setupPrivateNetworks - wanted %v, got %v`, want, len(PrivateIPBlocks))
	}
}

func TestIsPrivateIP(t *testing.T) {
	// TODO - Add more IPv4/IPv6 tests to each
	privateIPs := []string{"127.0.0.1", "192.168.3.5", "172.16.2.3", "255.255.255.255", "fe80::ffff:ffff:ffff:ffff", "::1", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "64:ff9b:1:ffff:ffff:ffff:ffff:ffcf"}
	for _, v := range privateIPs {
		if !IsPrivateIP(net.ParseIP(v), v) {
			t.Fatalf(`Error isPrivateIP: wanted true, got false for value: %v`, v)
		}
	}
	publicIPs := []string{"8.8.8.8", "32.3.54.1", "1.1.1.1", "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffcf", "2001::ffff:ffff:ffff:ffff:ffff:fcff"}
	for _, v := range publicIPs {
		if IsPrivateIP(net.ParseIP(v), v) {
			t.Fatalf(`Error isPrivateIP: wanted false, got true for value: %v`, v)
		}
	}
}

func TestLookupIP(t *testing.T) {
	results := LookupIPRecords("8.8.8.8")
	if len(results) != 1 {
		t.Fatalf(`Error lookupIPRecords - wanted 1, got %v`, len(results))
	}
	newresults := LookupIPRecords("non-existent")
	if len(newresults) != 1 {
		t.Fatalf(`Error lookupIPRecords - wanted 0, got %v`, len(newresults))
	}
	if newresults[0] != "None" {
		t.Fatalf(`Error lookupIPRecords - wanted None, got %v`, newresults[0])
	}
}
```

**Patterns:**
- Setup: Implicit - tests call functions directly with test data
- Teardown: Implicit - using `defer` or relying on garbage collection
- Assertion pattern: Manual comparison with `if` statements, calling `t.Fatalf()` for assertion failures

## Mocking

**Framework:** None detected

**Patterns:**
- No mocking framework in use
- Tests use real functions with real data
- Example: `TestLookupIP()` calls actual `LookupIPRecords()` function
- Network calls are made to real endpoints: DNS resolution to `1.1.1.1:53`

**What to Mock:**
- External network calls: DNS lookups, HTTP requests would benefit from mocking
- Database operations: MaxMind DB operations
- File I/O: File reading/writing operations
- NOTE: Current tests appear to avoid these

**What NOT to Mock:**
- Pure utility functions: `IsPrivateIP()` (tested directly)
- Data validation logic
- Local IP network checks

## Fixtures and Factories

**Test Data:**
- Hard-coded test slices in test functions:
  ```go
  privateIPs := []string{"127.0.0.1", "192.168.3.5", "172.16.2.3", ...}
  publicIPs := []string{"8.8.8.8", "32.3.54.1", "1.1.1.1", ...}
  ```
- No separate fixture files or factory functions observed
- Test data defined inline within test functions

**Location:**
- Test data defined at top of test functions in `network_test.go`
- No shared fixture setup file observed

## Coverage

**Requirements:** No coverage requirements enforced

**View Coverage:**
```bash
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out  # View in browser
```

## Test Types

**Unit Tests:**
- Scope: Individual functions
- Approach: Direct function calls with test data
- Example: `TestSetupPrivateNetworks()` tests single function behavior
- Coverage: IP validation logic, network setup

**Integration Tests:**
- Not explicitly separated from unit tests
- `TestLookupIP()` makes real DNS queries
- No tagged integration tests observed

**E2E Tests:**
- Not present in codebase
- Manual testing via command-line execution appears to be primary E2E approach

## Known Testing Gaps

**Untested Areas:**
- Parser functions in `parsers/` package: No test files found
- Main processing logic in `main.go`: No tests
- File I/O operations: No tests
- Database operations: No tests
- Helper functions in `helpers.go`: Limited coverage

**Comment indicating test gaps:**
```go
// TODO - Refactor downloadFile to betterr support testing
```

**High-risk untested functions:**
- All parser functions: `ParseCSV()`, `ParseJSON()`, `ParseMultiLineJSON()`, `ParseCEF()`, `ParseCLF()`, `ParseSyslog()`, `ParseKV()`, `ParseRaw()`, `ParseIISStyle()`
- File finding and processing: `findLogsToProcess()`, `processFile()`, `enrichLogs()`
- Configuration parsing: `parseArgs()` - handles all command-line arguments

## Test Execution Context

**Current Test Files:**
- `C:/Users/Joe/Documents/GitHub/tmplogboost/LogBoost/helpers/network_test.go` - Only test file in codebase (1 file total)

**Test Count:**
- 3 test functions identified:
  - `TestSetupPrivateNetworks()`
  - `TestIsPrivateIP()`
  - `TestLookupIP()`

**Testing Infrastructure:**
- No test utilities or helpers package
- No mock library imports
- No CI/CD test configuration files

## Recommendations for Testing

**For New Code:**
- Follow same pattern as existing tests in `network_test.go`
- Define test functions with `Test` prefix
- Use `t.Fatalf()` for assertion failures
- Keep test data inline or in separate test data files
- Use table-driven tests for multiple test cases

**For Parser Functions:**
- Create sample log files (small versions) for testing
- Test both happy path and error conditions
- Verify CSV output format matches expectations
- Test edge cases: empty files, malformed logs, missing fields

**For File Operations:**
- Consider using `afero` filesystem abstraction (already imported but commented out)
- Use temporary directories for testing file creation
- Clean up test files after execution

---

*Testing analysis: 2026-02-05*
