# Codebase Structure

**Analysis Date:** 2026-02-05

## Directory Layout

```
LogBoost/
├── main.go                 # CLI argument parsing, file orchestration, entry point
├── go.mod                  # Go module dependencies
├── feed_config.json        # Threat feed sources and configuration
├── README.md               # Project documentation and usage examples
├── LICENSE                 # Project license
├── .gitignore              # Git ignore patterns
├── .gitattributes          # Git attributes
├── .planning/              # Planning directory (generated)
│   └── codebase/           # Codebase documentation
├── helpers/                # Enrichment and utility functions
├── parsers/                # Log format-specific parsing modules
├── lbtypes/                # Type definitions and thread-safe containers
├── vars/                   # Global constants and regex patterns
├── tldparserr/             # TLD parser module (imported, not in repo)
├── whois_license/          # WhoIS licensing information (directory)
└── images/                 # Logo and documentation images
```

## Directory Purposes

**Root Directory:**
- Purpose: Project root, entry point, and configuration
- Contains: `main.go` (application entry), Go module files, JSON feed config, documentation
- Key files: `main.go`, `feed_config.json`

**helpers/ Directory:**
- Purpose: Enrichment logic, external API integrations, and utility functions
- Contains: IP enrichment, MaxMind database operations, DNS lookups, WhoIS queries, threat intelligence checks
- Key files: `helpers.go`, `maxmind.go`, `network.go`, `threatIntel.go`, `whois.go`, `ipNetGen.go`, `network_test.go`

**parsers/ Directory:**
- Purpose: Log format detection and parsing
- Contains: 9 format-specific parsers, each handling a different log type
- Key files:
  - `parse_csv.go`: Process CSV files (columns with headers)
  - `parse_json.go`: Process JSON-lines format (one JSON object per line)
  - `parse_json_multi.go`: Process multi-line JSON blobs (e.g., CloudTrail exports)
  - `parse_iis_w3c.go`: Process IIS and W3C extended log format
  - `parse_cef.go`: Parse Common Event Format (CEF) logs
  - `parse_clf.go`: Parse Common Log Format (CLF) and NCSA CLF
  - `parse_syslog.go`: Parse SYSLOG format (generic/RFC3164/RFC5424)
  - `parse_kv.go`: Parse key-value style logs with custom separators/delimiters
  - `parse_raw.go`: Fallback raw text parser using regex IP extraction

**lbtypes/ Directory:**
- Purpose: Shared type definitions and thread-safe data structures
- Contains: MaxMind response types, IP cache, job tracking, wait group wrappers
- Key files: `typesMethods.go` (single file with all types and methods)

**vars/ Directory:**
- Purpose: Global application state, constants, and regex patterns
- Contains: MaxMind DB file mappings, output column names, regex patterns, IP private range definitions
- Key files: `vars.go` (single file with all constants and globals)

**tldparserr/ Directory:**
- Purpose: External TLD parsing module (imported package)
- Note: Not committed to repo, imported via module

**whois_license/ Directory:**
- Purpose: WhoIS service licensing and attribution
- Note: Contains licensing information for WhoIS lookups

**images/ Directory:**
- Purpose: Documentation assets
- Contains: Logo and example output screenshots

## Key File Locations

**Entry Points:**
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\main.go`: CLI initialization and orchestration

**Configuration:**
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\feed_config.json`: Threat intelligence feed definitions
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\go.mod`: Dependency management

**Core Logic:**
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\helpers\helpers.go`: General enrichment utilities (enrichRecord, enrichment helpers)
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\helpers\maxmind.go`: MaxMind database discovery and download
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\helpers\network.go`: DNS resolution, HTTP clients, network validation
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\helpers\threatIntel.go`: Threat database operations (query, build, ingest)
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\helpers\whois.go`: WhoIS server lookups
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\parsers\parse_csv.go`: CSV parsing and enrichment
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\parsers\parse_json.go`: JSON-lines parsing
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\parsers\parse_json_multi.go`: Multi-line JSON parsing
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\parsers\parse_iis_w3c.go`: IIS/W3C log parsing

**Data Models:**
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\lbtypes\typesMethods.go`: All type definitions and their methods

**Global State:**
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\vars\vars.go`: Constants, regexes, file paths, status maps

**Testing:**
- `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\helpers\network_test.go`: Network utility tests

## Naming Conventions

**Files:**
- `parse_*.go`: Parser modules (format type in name)
- `*_test.go`: Go test files
- Lowercase with underscores separating words

**Directories:**
- Lowercase plural or descriptor names
- `helpers`, `parsers`, `lbtypes`, `vars`, `tldparserr`, `whois_license`, `images`

**Functions:**
- Exported (public): PascalCase (e.g., `ProcessCSV`, `enrichRecord`, `SetupLogger`)
- Unexported (private): camelCase (e.g., `findLogsToProcess`, `visit`, `setupHeaders`)
- Descriptive names indicating action or type (e.g., `enrichRecord`, `CheckIP`, `ParseJSON`)

**Variables:**
- Package-level exports: PascalCase (e.g., `IPCacheMap`, `LogsToProcess`, `MaxMindStatus`)
- Local variables: camelCase (e.g., `inputFile`, `outputFile`, `ipString`)
- Constants: ALL_CAPS (e.g., `LogFile`, `ExtraKeysColumnName`)
- Thread-safe map/struct names indicate purpose (e.g., `IPCache`, `SizeTracker`, `RunningJobs`)

**Types:**
- Exported (public): PascalCase (e.g., `City`, `ASN`, `Domain`, `IPCache`, `SizeTracker`)
- Struct fields: PascalCase (e.g., `AutonomousSystemOrganization`, `Names`, `IsAnonymousProxy`)
- Struct tags: `maxminddb` for MaxMind field mapping, `json` for JSON marshaling

## Where to Add New Code

**New Log Format Parser:**
- Primary code: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\parsers\parse_[format].go`
- Pattern: Follow existing parser structure
  - Implement `Check[Format]()` detection function returning type indicator
  - Implement `Parse[Format]()` function accepting databases, arguments, file paths
  - Extract headers using similar pattern to `setupHeaders()` in CSV parser
  - Iterate records and call `helpers.enrichRecord()` for enrichment
  - Write enriched records via CSV writer
- Register in format detection cascade in `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\main.go` (processFile function, lines 280-450)

**New Enrichment Source:**
- Implementation: Add function to `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\helpers\helpers.go` or new file in helpers
- Integration point: Call within `helpers.enrichRecord()` (line 295+) or as separate enrichment step
- Output columns: Add column names to `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\vars\vars.go` (e.g., `ThreatFields`, `DNSFields`)

**New CLI Flag:**
- Define: `main.go` parseArgs function (lines 24-62)
- Store in arguments map: Pass through to enrichment functions
- Validate: Add validation logic in `parseArgs()` after flag definition

**Utilities/Helpers:**
- File location: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\helpers\helpers.go` (if general) or specific helper file
- File naming: If specialized domain, create `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\helpers\[domain].go`
- Examples: `maxmind.go` (MaxMind ops), `network.go` (network ops), `threatIntel.go` (TI ops), `whois.go` (WhoIS ops)

**New Type/Model:**
- File location: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\lbtypes\typesMethods.go`
- Pattern: Define struct, implement receiver methods for thread-safe access
- Naming: PascalCase type name, prefix with receiver type for method names (e.g., `(s *SizeTracker) AddBytes()`)

**New Global Constant/Regex:**
- File location: `C:\Users\Joe\Documents\GitHub\tmplogboost\LogBoost\vars\vars.go`
- Pattern: Define at package level, use meaningful names
- Related data: If adding output column type, add to corresponding slice (e.g., `GeoFields`, `ThreatFields`)

## Special Directories

**vars/ Directory:**
- Purpose: Global application state and constants
- Generated: No
- Committed: Yes
- Contents: Regex patterns, file mappings, column names, private IP CIDR ranges
- Note: Acts as centralized configuration; modified at startup to populate MaxMind file locations and status

**.planning/ Directory:**
- Purpose: Generated documentation (created by CI/planning tools)
- Generated: Yes
- Committed: No
- Contents: ARCHITECTURE.md, STRUCTURE.md, CONVENTIONS.md, etc.

---

*Structure analysis: 2026-02-05*
