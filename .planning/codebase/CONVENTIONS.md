# Coding Conventions

**Analysis Date:** 2026-02-05

## Naming Patterns

**Files:**
- Snake case with descriptive names: `parse_csv.go`, `parse_json.go`, `network_test.go`
- Parser files follow pattern: `parse_[format].go`
- Type/struct files: `typesMethods.go`, `tld_parser.go`
- Test files use suffix: `_test.go` (e.g., `network_test.go`)

**Functions:**
- PascalCase for exported functions: `CheckJSON()`, `ParseCSV()`, `ProcessFile()`, `SetupPrivateNetworks()`, `DownloadFile()`
- camelCase for unexported functions: `setupHeaders()`, `decodeJson()`, `decodeJsonKeys()`, `parseDeepJSONKeys()`, `identifySyslogHeader()`
- Function names are descriptive: `CheckIISorW3c()`, `ParseMultiLineJSONHeaders()`, `RegexFirstPublicIPFromString()`

**Variables:**
- camelCase for local variables: `inputFile`, `outputFile`, `logDir`, `fileProcessed`, `ipAddressColumn`
- camelCase for package-level variables: `PrivateIPBlocks`, `resolver`, `IDB_Http_Client`
- Constants use ALL_CAPS: `LogFile`, `ExtraKeysColumnName`
- Underscore-separated for map keys: `"IPcolumn"`, `"JSONcolumn"`, `"maxgoperfile"`, `"batchsize"`
- Descriptive slice naming: `headers`, `jsonKeys`, `privateIPs`, `publicIPs`

**Types:**
- PascalCase for struct names: `City`, `ASN`, `Domain`, `IPCache`, `DBRefs`, `ShodanIDBResponse`, `WaitGroupCount`, `SizeTracker`, `RunningJobs`
- Field names within structs use PascalCase and are exported: `AutonomousSystemOrganization`, `AutonomousSystemNumber`, `IsAnonymousProxy`
- JSON struct tags use snake_case matching the JSON field names: `maxminddb:"names"`, `json:"cpes"`, `json:"hostnames"`

## Code Style

**Formatting:**
- Go standard formatting (implicitly enforced by `gofmt`)
- 4-space indentation (Go standard)
- Brace style: One True Brace (opening brace on same line)
- Max line length: No hard limit observed, but practical limit appears to be around 120 characters

**Linting:**
- No explicit linter configuration file present
- Follows Go conventions and idioms
- Error handling is explicit with `if err != nil` pattern throughout

## Import Organization

**Order:**
1. Standard library imports (e.g., `"database/sql"`, `"encoding/json"`, `"fmt"`, `"os"`)
2. External third-party imports (e.g., `"github.com/joeavanzato/logboost/helpers"`)
3. Package-local imports (relative to current module)

**Style:**
- Grouped by type (standard, external, local) with blank lines between groups
- Alphabetically sorted within groups
- Example from `main.go`:
  ```go
  import (
      "database/sql"
      "encoding/json"
      "errors"
      "flag"
      "fmt"
      "github.com/joeavanzato/logboost/helpers"
      "github.com/joeavanzato/logboost/lbtypes"
      "github.com/joeavanzato/logboost/parsers"
      "github.com/joeavanzato/logboost/vars"
      _ "github.com/mattn/go-sqlite3"
      "github.com/oschwald/maxminddb-golang"
      "github.com/rs/zerolog"
      "io/fs"
      "os"
      "path/filepath"
      "strings"
      "sync"
      "time"
  )
  ```

**Path Aliases:**
- Blank import for side effects: `_ "github.com/mattn/go-sqlite3"` to register database driver

## Error Handling

**Patterns:**
- Explicit error checking: `if err != nil` on every function call that can error
- Early return on error: Function returns immediately upon error detection
- Error context via logger: `logger.Error().Msg(err.Error())` or `logger.Error().Msgf(...)`
- Error propagation: Errors are returned to caller for higher-level handling
- Examples from codebase:
  ```go
  if err != nil {
      logger.Error().Msg(err.Error())
      return err
  }

  if err != nil {
      logger.Error().Msgf("Error Processing File: %v", err.Error())
      return
  }
  ```
- Sentinel errors: Using `errors.Is()` for specific error checking, e.g., `errors.Is(err, os.ErrNotExist)`

## Logging

**Framework:** `github.com/rs/zerolog` (structured logging)

**Patterns:**
- Logger initialized in `helpers.SetupLogger()` - `C:/Users/Joe/Documents/GitHub/tmplogboost/LogBoost/helpers/helpers.go`
- Three log levels observed: `Info()`, `Error()`, `Trace()`
- Logging with context: `logger.Info().Msgf("Format: %v", value)`
- Structured logging with methods chaining: `logger.Error().Msg()`
- Timestamp automatically included via: `logger.With().Timestamp().Logger()`
- Output to both console and file: `logboost.log`
- Typical logging:
  ```go
  logger.Info().Msgf("Downloading MaxMind %v DB to path: %v", key, filepath)
  logger.Error().Msgf("Could not find directory: %v", logDir)
  ```

## Comments

**When to Comment:**
- Links to external documentation: `//https://docs.nxlog.co/integrate/cef-logging.html`
- Algorithm explanation: Comments explaining CEF format variations (lines 34-45 in `parse_cef.go`)
- TODO items for future work: `// TODO - Support Cross-Platform Compilation` (appears multiple times)
- Design decisions: `// I do not like how the below path splitting/joining is being achieved - I'm sure there is a more elegant solution...`
- Data structure purpose: `// Used to track overall data size processed by the script - accessed by multiple goroutines concurrently so we make it threadsafe`

**JSDoc/TSDoc:**
- Not applicable for Go
- Function documentation uses Go convention comments preceding function definition
- Example in `ipNetGen.go`:
  ```go
  // Increment increments the given net.IP by one bit.
  // Incrementing the last IP in an IP space (IPv4, IPV6) is undefined.

  // IPNetGenerator is a net.IPnet wrapper that you can iterate over

  // NewIPNetGenerator creates a new IPNetGenerator from a CIDR string, or an error if the CIDR is invalid.
  ```

## Function Design

**Size:** Functions vary significantly; some are quite large (100+ lines like `enrichLogs()`, `processFile()`)

**Parameters:**
- Multiple parameters passed via individual arguments (not wrapped in structs except for specialized cases)
- Common pattern: `(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, domainDB maxminddb.Reader, arguments map[string]any, ...)`
- Context-dependent parameters in maps: `arguments map[string]any`, `tempArgs map[string]any`

**Return Values:**
- Single or multiple returns with error as last return
- Error handling: `(bool, []string, error)`, `(error)`, `(int)`, `(map[string]any, error)`
- Example: `func CheckJSON(logger zerolog.Logger, file string, fullParse bool) (bool, []string, error)`

## Module Design

**Exports:**
- Capitalized names for exported symbols from packages
- Each package has clear responsibility: `helpers/`, `parsers/`, `lbtypes/`, `vars/`

**Barrel Files:**
- No barrel files (index.go) observed
- Each file in a package is standalone with appropriate imports

## Concurrency Patterns

**Goroutines and Channels:**
- WaitGroup usage for synchronization: `lbtypes.WaitGroupCount` wraps `sync.WaitGroup`
- RWMutex for thread-safe map access:
  ```go
  var IPCacheMap = make(map[string]IPCache)
  var IPCacheMapLock = sync.RWMutex{}
  ```
- Channel-based communication for worker pools: `recordChannel := make(chan []string)`
- Job tracking pattern: `lbtypes.RunningJobs` with `Mw sync.RWMutex{}`

**Patterns observed:**
- Defer for cleanup: `defer f.Close()`, `defer db.Close()`
- Defer with locks: `defer IPCacheMapLock.RUnlock()`
- Concurrent file processing with max concurrent files limit

## Constants and Configuration

**Global variables in `vars/vars.go`:**
- Regex patterns: `AuditLogIPRegex`, `Ipv6_regex`, `Ipv4_regex`
- Database file references: `MaxMindFiles`, `MaxMindURLs`, `MaxMindStatus`, `MaxMindFileLocations`
- Field slices for CSV output: `GeoFields`, `ThreatFields`, `DNSFields`, `WhoisDomainFields`, `WhoisIPFields`, `IDBFields`
- Cache file paths: `DnsCacheFile`, `WhoisCacheFile`, `IDBCacheFile`
- In-memory caches: `Dnsfastcache`, `Whoisfastcache`, `IDBfastcache`

---

*Convention analysis: 2026-02-05*
