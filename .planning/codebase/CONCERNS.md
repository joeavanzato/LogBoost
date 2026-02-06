# Codebase Concerns

**Analysis Date:** 2026-02-05

## Tech Debt

**Cross-Platform Path Handling:**
- Issue: Hardcoded Windows path separators (`\\`) throughout codebase preventing cross-platform compilation
- Files: `main.go` (lines 233, 239, 252), `helpers/maxmind.go` (line 86), `helpers/threatIntel.go` (lines 171, 263, 427), `helpers/helpers.go` (line 154, 165)
- Impact: Application only runs on Windows; Linux/macOS support blocked; deployment flexibility severely limited
- Fix approach: Use `filepath.Join()`, `filepath.Separator`, and `path/filepath` package consistently throughout codebase to generate platform-agnostic paths

**Dynamic Type Assertions Without Validation:**
- Issue: Extensive use of type assertions on `map[string]any` arguments without checking correctness first
- Files: `main.go` (lines 145, 174, 191, 198-216 and throughout)
- Impact: Runtime panics if argument parsing fails or user provides incorrect flag types; no safety checks before casting
- Fix approach: Validate type assertions (e.g., `val, ok := arguments["key"].(type)`) before use; return early with error messages on assertion failure

**Unprotected Panic in Logger Initialization:**
- Issue: `panic()` calls in `SetupLogger()` at line 37-39 in `helpers/helpers.go`
- Files: `helpers/helpers.go` (lines 37, 39)
- Impact: Application crashes during startup without recoverable error handling; nested panic with nil argument (line 37) produces unhelpful error message
- Fix approach: Return errors from `SetupLogger()` and handle them in `main()`; remove panic calls; use structured error returns

**Concurrency Bug in File Processing:**
- Issue: Documented concurrency bug at `main.go:281` - "not sure yet - using concurrentfiles = 10 will work when default will not"
- Files: `main.go` (line 281), `main.go` (lines 254-270 waitForOthers loop)
- Impact: Race condition or deadlock with default settings (concurrentfiles=100); requires manual reduction to 10 for stability; unpredictable failures
- Fix approach: Debug the wait/synchronization logic in the job tracker; add proper synchronization primitives; write concurrency tests

**Suboptimal Synchronization Primitives:**
- Issue: Custom implementation using `sync.RWMutex` instead of `sync.Map` for IP caching
- Files: `lbtypes/typesMethods.go` (lines 65-79)
- Impact: Performance uncertainty; potential lock contention under high concurrency; TODO indicates unresolved performance question
- Fix approach: Benchmark `sync.Map` vs current RWMutex approach; migrate to sync.Map if performance improves; refactor cache struct as suggested in TODO

## Known Bugs

**Array Index Out of Bounds - MaxMind API Parsing:**
- Symptoms: Panic if MaxMind API key is malformed (missing colon)
- Files: `helpers/maxmind.go` (lines 83-84)
- Trigger: Calling `DownloadMaxMindDatabases()` with API key that doesn't contain `:` separator
- Details: `strings.Split(apikey, ":")[0]` and `[1]` without length check
- Workaround: Validate API key format before calling; ensure environment variable or file contains `ACCOUNTID:APIKEY` format

**Array Index Out of Bounds - Empty mm_api.txt:**
- Symptoms: Panic when reading MaxMind API key file
- Files: `helpers/maxmind.go` (lines 163-164)
- Trigger: `mm_api.txt` exists but is empty (no lines)
- Details: `FileToSlice("mm_api.txt", logger)[0]` accessed without bounds check; TODO at line 163 notes this
- Workaround: Ensure `mm_api.txt` contains at least one line with valid API key

**DNS Record Parsing Without Validation:**
- Symptoms: Nil pointer or index error if DNS cache returns malformed data
- Files: `helpers/helpers.go` (line 490)
- Trigger: Corrupted DNS cache or unexpected response format
- Details: `strings.Split(string(value), "|")` assumes specific delimited format without validation

**Category Mapping Lookup Failure:**
- Symptoms: Panic or zero value returned for unknown threat intelligence categories
- Files: `helpers/threatIntel.go` (lines 301, 304)
- Trigger: Category from feed doesn't exist in `CategoryMap`; returns 0 for unknown categories
- Details: `CategoryMap[cat]` lookup without checking if key exists; maps to unchecked DB RowID

## Security Considerations

**Credentials in Command-Line Arguments:**
- Risk: MaxMind API key passed via `-api` flag is visible in process listings and shell history
- Files: `main.go` (line 32)
- Current mitigation: Recommends environment variable `MM_API` or file-based `mm_api.txt` as fallback
- Recommendations: Document security best practices; warn against command-line API keys; implement secure credential handling; consider reading from secure vault on production

**HTTP Downloads Without Certificate Verification:**
- Risk: No explicit certificate pinning or validation during MaxMind database downloads
- Files: `helpers/network.go` (lines 54-80, 82-112)
- Current mitigation: Uses HTTPS URLs; relies on system CA store
- Recommendations: Add certificate pinning for `download.maxmind.com`; log HTTPS verification details; consider checksum validation of downloaded files

**No Input Validation on File Paths:**
- Risk: Potential path traversal if user-supplied paths aren't validated
- Files: `main.go` (line 145, 174 - arguments)
- Current mitigation: Uses `filepath` functions which provide some protection
- Recommendations: Implement explicit path validation; reject relative paths with `..`; validate that output directory is writable

**Unencrypted Local Cache Storage:**
- Risk: DNS cache stored in plaintext in `dns.cache` directory; threat intelligence database in `threats.db`
- Files: `helpers/helpers.go` (DNS caching logic); `helpers/threatIntel.go` (database operations)
- Current mitigation: Cache stored in local working directory
- Recommendations: Document sensitivity of cached data; consider encryption for sensitive indicators; implement cache cleanup options

**Weak/No Validation on External Downloads:**
- Risk: Threat intelligence feeds downloaded from `feed_config.json` URLs without integrity checks
- Files: `helpers/threatIntel.go` (lines 1-50+)
- Current mitigation: Downloads via HTTP/HTTPS
- Recommendations: Add SHA256 checksum validation for downloaded feeds; implement signed manifest verification; rate-limit feed updates

## Performance Bottlenecks

**Database File Reopened Per-Record:**
- Problem: MaxMind databases opened separately for EACH file processed (not per-goroutine batch)
- Files: `main.go` (lines 288-321)
- Cause: `maxminddb.Open()` called multiple times instead of reusing reader handles
- Impact: Excessive file I/O; potential lock contention on database files
- Improvement path: Refactor to open databases once and pass reader references; implement database connection pooling

**Synchronous DNS Lookups Block Processing:**
- Problem: `LookupIPRecords()` performs blocking network I/O in serial within record processing pipeline
- Files: `helpers/network.go` (lines 114-122), `helpers/helpers.go` (line 411)
- Cause: `net.DefaultResolver.LookupAddr()` blocks; single DNS lookup per record
- Impact: DNS requests become bottleneck; batch timeouts with large datasets; recommended to reduce batch size
- Improvement path: Implement DNS query batching; use concurrent DNS resolver with rate limiting; add DNS prefetch/parallel lookup

**Unbuffered CSV Writing For Large Files:**
- Problem: Lines buffered in memory slice before writing; buffersize configurable but may OOM on massive files
- Files: `helpers/helpers.go` (lines 217-234)
- Cause: All buffered lines held in memory before `csv.Writer.WriteAll()`
- Impact: Memory usage proportional to buffer size; potential OOM on large datasets
- Improvement path: Use streaming writer instead of buffering; flush frequently; implement tiered buffering strategy

**Regex Compilation Per-Record:**
- Problem: IP regex patterns potentially recompiled or evaluated against every record
- Files: `vars/` (regex patterns used in helpers)
- Impact: Redundant regex compilation/matching overhead
- Improvement path: Pre-compile all regex patterns at startup; cache compiled patterns in global struct

**Synchronous WHOIS Lookups:**
- Problem: `WhoIS()` function performs serial lookups for each domain
- Files: `helpers/whois.go` (entire file - 204 lines)
- Impact: Cascading network I/O delays; significant slowdown when `-whois` flag enabled
- Improvement path: Implement WHOIS caching (similar to DNS cache); batch WHOIS requests; add timeout controls

## Fragile Areas

**JSON Parsing In parse_json_multi.go:**
- Files: `parsers/parse_json_multi.go` (entire file - 432 lines)
- Why fragile: Complex multi-blob JSON parsing with manual state tracking (openCount, closeCount, currentBlob); TODO error handling at line 122; logic depends on character-by-character parsing without formal parser
- Safe modification: Add comprehensive unit tests for malformed JSON; implement proper JSON streaming parser; add error recovery paths
- Test coverage: Minimal - no tests visible for edge cases (nested arrays, escaped quotes, mixed formats)

**IsPrivateIP() IPv6 Incomplete:**
- Files: `helpers/helpers.go` (lines 124-142)
- Why fragile: IPv6 private network checks TODO at line 869 unimplemented; function checks IPv4 blocks but IPv6 handling incomplete
- Safe modification: Implement IPv6 private network checks (fc00::/7, fe80::/10); add unit tests for IPv6 ranges; validate against IANA specs
- Test coverage: Tests only check IPv4 at `helpers/network_test.go`

**Type Assertion Error Handling:**
- Files: `main.go` (throughout argument parsing)
- Why fragile: No panic recovery; incorrect CLI flag combinations cause crashes
- Safe modification: Add comprehensive type checking; return validation errors; add integration tests for all flag combinations
- Test coverage: No visible unit tests for argument parsing

**CEF Parser Logic:**
- Files: `parsers/parse_cef.go` (387 lines)
- Why fragile: TODO at line 98 (incomplete functionality); TODO at line 164 (unimplemented sorting); custom parsing logic without formal CEF spec validation
- Safe modification: Implement full CEF standard compliance; add CEF spec validation tests; reference RFC 3164 / ArcSight CEF spec
- Test coverage: No visible tests

**Syslog Parser Incomplete:**
- Files: `parsers/parse_syslog.go` (line 20 TODO - incomplete parsing)
- Why fragile: Parser definition incomplete; TODO indicates syslog format parsing not fully implemented
- Safe modification: Implement full RFC 3164/RFC 5424 syslog compliance; add tests for various syslog formats
- Test coverage: No visible tests

## Scaling Limits

**Goroutine Explosion:**
- Current capacity: Default allows 100 concurrent files × 20 goroutines per file = 2,000 goroutines
- Limit: README states machines with 4GB RAM can handle ~1M goroutines, but practical limits depend on data size
- Issue: With 10,000 input files and concurrentfiles=100 + maxgoperfile=20, could spawn 200,000 goroutines
- Scaling path: Implement adaptive goroutine pool with bounded queue; add goroutine count monitoring; implement backpressure mechanism

**Memory Buffer Accumulation:**
- Current capacity: Write buffer (default 2,000 lines) × multiple concurrent output files can consume significant RAM
- Limit: Large CSV files with thousands of columns can cause memory spikes
- Issue: No memory limits enforced; OOM possible on constrained systems
- Scaling path: Implement memory-aware buffer sizing; add heap monitoring; implement spill-to-disk for large buffers

**Database File Descriptor Limits:**
- Current capacity: Each `processFile()` opens 3-4 MaxMind database files; with 100 concurrent files = 300-400 FDs
- Limit: OS file descriptor limits (typically 1024-4096) easily exceeded
- Scaling path: Implement database connection pooling; share readers across goroutines; implement FD monitoring

**DNS Query Rate Limits:**
- Current capacity: No rate limiting on DNS queries; can generate hundreds per second
- Limit: Upstream DNS servers (Google, Cloudflare, etc.) throttle after ~100-1000 queries/second
- Scaling path: Implement DNS query rate limiter; add exponential backoff for throttled responses; support custom resolver configuration

## Scaling Limits

**Threat Intelligence Database Growth:**
- Current capacity: Threat feed ingestion creates SQLite database with unlimited row growth
- Limit: SQLite performance degrades with very large datasets; no indexing strategy documented
- Scaling path: Add database indexing strategy; implement data retention policies; consider migrating to larger DB for enterprise use

## Dependencies at Risk

**MaxMind Database Format Lock-In:**
- Risk: Application tightly coupled to MaxMind MMDB format and specific field names
- Impact: Breaks if MaxMind changes DB structure; no abstraction layer
- Migration plan: Create abstraction interface for geolocation providers; support alternative GeoIP sources (IP2Location, etc.)

**SQLite for Threat Intelligence:**
- Risk: SQLite has concurrency limitations; not suitable for production threat intel with high write volumes
- Impact: Contention during threat feed updates while queries running; potential data corruption under heavy load
- Migration plan: Implement pluggable database backend; support PostgreSQL/MySQL for production; add transaction isolation levels

**Hardcoded Column Names:**
- Risk: CSV processing assumes specific column names (IP address, AuditData per Azure); breaks with non-standard schemas
- Impact: Users must rename columns or transform data before processing
- Migration plan: Allow column name mapping; implement auto-detection of IP columns; add data schema validation

## Missing Critical Features

**No Resume/Checkpoint System:**
- Problem: If process crashes after hours of processing, must restart from beginning
- Blocks: Resuming large job; implementing reliable batch processing
- Solution: Implement checkpoint file; track processed file offsets; allow resume flag

**No Rate Limiting on External APIs:**
- Problem: Can overwhelm DNS/WHOIS servers or get rate-limited/blocked
- Blocks: Reliable operation on large datasets; enterprise deployment
- Solution: Add configurable rate limiters; implement token bucket for API requests; add retry backoff

**No Duplicate Detection:**
- Problem: Same IP enriched multiple times if it appears in same file
- Blocks: Performance optimization; duplicate elimination in output
- Solution: Implement per-file deduplication before enrichment; add bloom filter for cross-file tracking

**Missing Data Validation:**
- Problem: No schema validation for input CSVs; malformed data causes silent failures
- Blocks: Reliability; error reporting
- Solution: Add CSV schema definition; implement validation with detailed error messages

**No Incremental Output Updates:**
- Problem: Each run must re-enrich all data; no way to add new columns to existing output
- Blocks: Iterative enrichment workflows
- Solution: Implement column-append mode; support reading existing output and adding new enrichments

## Test Coverage Gaps

**Unit Tests Missing for Core Logic:**
- What's not tested: Argument parsing, type assertions, path handling, main file processing loop
- Files: `main.go` (entire file - no tests visible)
- Risk: Refactoring breaks untested paths; type assertion errors undetected until runtime
- Priority: High

**Parser Edge Cases Untested:**
- What's not tested: Malformed JSON, incomplete CEF records, missing syslog headers, truncated IIS logs
- Files: `parsers/` (all parsers - minimal/no test files)
- Risk: Parser crashes on real-world malformed data; silent data loss
- Priority: High

**Network Function Testing:**
- What's not tested: DNS timeout handling, WHOIS connection failures, MaxMind download failures, HTTP errors
- Files: `helpers/network.go` (55-line TODO at line 55 noting refactor needed for testing), `helpers/network_test.go` (51 lines - minimal coverage)
- Risk: Network failures cause unhandled panics; no graceful degradation
- Priority: High

**Concurrency Testing:**
- What's not tested: Race conditions, deadlocks, goroutine leaks, high concurrency scenarios
- Files: `main.go` (known concurrency bug at line 281), `lbtypes/typesMethods.go` (sync primitives)
- Risk: Concurrency bugs only appear under load; unpredictable failures in production
- Priority: Critical

**Integration Tests Absent:**
- What's not tested: End-to-end workflows, multi-file processing, cache persistence, threat feed ingestion
- Files: Entire codebase
- Risk: Component interactions untested; system-level bugs undetected
- Priority: High

---

*Concerns audit: 2026-02-05*
