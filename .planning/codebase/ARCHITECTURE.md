# Architecture

**Analysis Date:** 2026-02-05

## Pattern Overview

**Overall:** Pipeline with Pluggable Parsers

**Key Characteristics:**
- Log conversion and enrichment pipeline with format-detection and routing
- Multiple parallel file processing with concurrent goroutine management
- Pluggable parser architecture supporting 9+ log format types
- External data source integration (MaxMind, DNS, WhoIS, Threat Intel databases)
- Thread-safe caching for DNS, WhoIS, and threat intelligence lookups

## Layers

**Entry Point (main.go):**
- Purpose: Parse command-line arguments, initialize resources, orchestrate workflow
- Location: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\main.go`
- Contains: CLI argument parsing, logger setup, file discovery, main orchestration functions
- Depends on: All helper packages, all parser packages, logging (zerolog)
- Used by: Called once at startup

**File Discovery & Routing (main.go - findLogsToProcess, processFile):**
- Purpose: Walk input directory, identify files, route to appropriate parser based on format detection
- Location: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\main.go` (lines 144-171, 280-464)
- Contains: Directory traversal, format detection decision tree, goroutine spawning
- Depends on: Parser detection functions
- Used by: enrichLogs orchestrator

**Parsing Layer (parsers package):**
- Purpose: Convert various log formats to CSV records with header extraction
- Location: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\parsers\`
- Contains: 9 format-specific parser modules (CSV, JSON, IIS/W3C, CEF, CLF, Syslog, KV, Multi-line JSON, Raw)
- Depends on: helpers for enrichment, lbtypes for data structures
- Used by: processFile dispatcher

**Enrichment Layer (helpers package):**
- Purpose: Enhance log records with geolocation, threat intel, DNS, WhoIS data
- Location: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\helpers\`
- Contains: IP enrichment, DNS lookups, WhoIS queries, threat database checks, MaxMind DB lookups
- Depends on: lbtypes, vars, network clients (http, dns)
- Used by: All parsers during record processing

**Data Models (lbtypes package):**
- Purpose: Struct definitions and thread-safe data containers
- Location: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\lbtypes\typesMethods.go`
- Contains: MaxMind response types (City, ASN, Domain), thread-safe IP cache, job tracker, wait group wrapper
- Depends on: maxminddb library, sync primitives
- Used by: All layers for data passing

**Global State (vars package):**
- Purpose: Application constants, regex patterns, file paths, cached settings
- Location: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\vars\vars.go`
- Contains: MaxMind DB file locations and status, regex patterns for IP detection, output column names, fastcache instances
- Depends on: regexp, net, external fastcache library
- Used by: All packages for shared configuration

## Data Flow

**Primary Enrichment Pipeline:**

1. `main()` parses arguments → `parseArgs()` returns configuration map
2. `findLogsToProcess()` walks input directory, populates `vars.LogsToProcess` with file paths
3. `enrichLogs()` spawns goroutines (up to `concurrentfiles` limit) to process files
4. Each goroutine calls `processFile()` which:
   - Opens MaxMind databases (ASN, City, Country, Domain)
   - Detects log format via cascading format checks (IIS/W3C → JSON → CEF → CLF → Syslog → KV → Raw)
   - Routes to appropriate parser (e.g., `parsers.ProcessCSV()`)
5. Parser reads records, extracts headers, identifies IP/JSON columns
6. For each record, calls `helpers.enrichRecord()` which:
   - Extracts IP address (via column index or regex)
   - Looks up geolocation in MaxMind databases
   - Checks threat intelligence database if enabled
   - Performs DNS reverse lookup if enabled
   - Performs WhoIS lookup if enabled
7. Enriched records written to output CSV file
8. File statistics tracked via `sizeTracker`, output cached via fastcache

**Threat Intelligence Workflow (optional):**

1. `helpers.BuildThreatDB()` reads `feed_config.json` and downloads threat feeds
2. Feeds stored in SQLite database (`threat_intel.db`)
3. During enrichment, `helpers.CheckIPinTI()` queries database for IP matches
4. Matches include threat category, feed name, feed count

**Configuration & Resource Loading:**

1. MaxMind API key resolved: env var (`MM_API`) → file (`mm_api.txt`) → command-line flag
2. MaxMind databases located via glob in working directory or specified `dbdir`
3. Missing databases auto-downloaded if API key available
4. Threat database loaded into memory if `-useti` flag specified

**State Management:**

- `vars.IPCacheMap`: In-memory thread-safe map of already-enriched IPs (keyed by IP string)
- `vars.LogsToProcess`: Global slice populated during directory walk
- `vars.MaxMindFileLocations`, `vars.MaxMindStatus`: Track available databases
- `vars.Dnsfastcache`, `vars.Whoisfastcache`, `vars.IDBfastcache`: Persistent cache files for DNS, WhoIS, Shodan responses

## Key Abstractions

**Parser Interface (implicit):**
- Purpose: Format-specific log parsing with header detection and record extraction
- Examples: `parsers.ProcessCSV()`, `parsers.ParseJSON()`, `parsers.ParseIISStyle()`, `parsers.ParseCEF()`, `parsers.ParseKV()`
- Pattern: Each parser follows pattern: detect format → extract headers → iterate records → apply enrichment

**Enrichment Function:**
- Purpose: Transform a single log record by adding geolocation and threat intelligence columns
- Examples: `helpers.enrichRecord()` (main enrichment), `helpers.DoDNSEnrichment()`, `helpers.DoDomainWhoisenrichment()`
- Pattern: Take raw record → extract IP → enrich from external sources → return expanded record

**Thread-Safe Data Containers:**
- Purpose: Enable concurrent access without race conditions
- Examples: `lbtypes.SizeTracker` (RWMutex), `lbtypes.RunningJobs` (RWMutex), `lbtypes.WaitGroupCount` (atomic counter)
- Pattern: RWMutex for read-heavy operations, atomic operations for simple counters

## Entry Points

**CLI Entry (main):**
- Location: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\main.go` (line 487)
- Triggers: Binary execution
- Responsibilities: Parse arguments, setup logger and databases, dispatch to appropriate subcommand or enrichment workflow

**Format Detection Entry (processFile):**
- Location: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\main.go` (line 280)
- Triggers: Per-file goroutine spawn from enrichLogs
- Responsibilities: Open databases, cascade through format checks, route to correct parser

**Subcommand Entries (main function):**
- `--buildti`: Build threat intelligence database from feeds
- `--updateti`: Update existing threat intelligence database
- `--summarizeti`: Display threat database contents
- `--tifeeds`: List ingested threat feeds
- `--ip`: Single IP enrichment via stdout
- Default: File enrichment pipeline

## Error Handling

**Strategy:** Log-and-continue with graceful degradation

**Patterns:**
- Missing databases: Log error, skip enrichment for that database type, continue processing
- Parse failures: Log error for file, mark as unprocessed, continue to next file
- Network failures (DNS, WhoIS, API): Log error, append "error" or "NA" values, continue
- Database failures: If threat DB unavailable, skip threat intelligence enrichment
- Invalid IP addresses: Return sentinel values ("NoIP", "PVT", "NA") instead of crashing

**Logging:**
- Framework: `zerolog` with console writer + file writer (`logboost.log`)
- Levels: Trace (all), Info (normal flow), Error (failures)
- Format: Timestamp + level + message

## Cross-Cutting Concerns

**Logging:**
- Centralized via `helpers.SetupLogger()`
- Used throughout for activity tracking and error reporting
- Writes to both console and `logboost.log` file

**Validation:**
- IP address format validation via `net.ParseIP()`
- Private IP checking via `helpers.IsPrivateIP()` against CIDR blocks in `helpers.PrivateIPBlocks`
- Regex-based fallback IP extraction via `vars.Ipv4_regex` and `vars.Ipv6_regex`

**Concurrency Control:**
- Per-file goroutine limit: `concurrentfiles` argument (default 100)
- Per-file thread limit: `maxgoperfile` argument (default 20)
- Per-goroutine batch size: `batchsize` argument (default 500)
- Output buffer size: `writebuffer` argument (default 2000)
- Wait group + job counter pattern in `lbtypes.RunningJobs`

---

*Architecture analysis: 2026-02-05*
