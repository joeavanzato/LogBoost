# External Integrations

**Analysis Date:** 2026-02-05

## APIs & External Services

**MaxMind Geolocation:**
- MaxMind GeoLite2 - IP geolocation data (ASN, Country, City)
  - SDK/Client: oschwald/maxminddb-golang v1.12.0
  - Auth: MaxMind License Key (format: `ACCOUNTID:APIKEY`)
  - Env vars: `MM_API` or file `mm_api.txt` in current working directory
  - Endpoints: `https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz`, `GeoLite2-City/download`, `GeoLite2-Country/download`
  - Data Files: Downloaded as tar.gz and extracted to MMDB files: `GeoLite2-ASN.mmdb`, `GeoLite2-City.mmdb`, `GeoLite2-Country.mmdb`
  - Implementation: `helpers/maxmind.go` (FindOrGetDBs, updateMaxMind, SetAPIUrls)
  - Usage: `main.go` parseArgs flag `-api`, `-updategeo`, `-dbdir`

**Shodan InternetDB:**
- Shodan InternetDB - Open vulnerability and service enumeration data for IPs
  - SDK/Client: Custom HTTP client in `helpers/helpers.go` (DoIDBEnrichment function)
  - Endpoint: `https://internetdb.shodan.io/` (2-second timeout via IDB_Http_Client)
  - Response: JSON with CPEs, hostnames, ports, tags, and vulnerabilities
  - Cache: VictoriaMetrics/fastcache with 1GB max (file: `idb.cache`)
  - Usage: Flag `-idb` enables live Shodan InternetDB enrichment
  - Data returned: `lb_IDB_cpes`, `lb_IDB_hostnames`, `lb_IDB_ports`, `lb_IDB_tags`, `lb_IDB_vulns` columns
  - Implementation: `helpers/helpers.go` lines 522-556

**Threat Intelligence Feeds:**
- Multiple external threat intelligence sources (30+ feeds configured)
  - Configuration: `feed_config.json` - JSON array of feed objects with name, URL, and type
  - Feeds include: AlienVault Reputation, Binary Defense Banlist, BotVrij, CINSSCORE, dan.me.uk Tor List, Blocklist.de (various ports), Emerging Threats, Feodo Tracker, OSINT.digitalside, and more
  - Implementation: `helpers/threatIntel.go` for feed ingestion, parsing, and SQLite database population
  - Storage: Local SQLite database (`threats.db`) indexed by IP address
  - Categories: suspicious, tor, malware, phishing, ransomware, etc. (defined per feed in feed_config.json)
  - Usage: Flags `-buildti` (initial build), `-updateti` (periodic updates), `-useti` (use for enrichment)
  - Data returned: `lb_ThreatCategories`, `lb_ThreatFeedCount`, `lb_ThreatFeeds` columns

**Threat Intelligence - Custom Ingestion:**
- Custom threat indicator files can be added to threat database
  - Implementation: `helpers/threatIntel.go`
  - Usage: Flags `-intelfile` (path), `-intelname` (name/tag), `-inteltype` (category)
  - Example: Datacenter ASN list (included in vars.go, ~19MB ASN list)

## Data Storage

**Databases:**
- SQLite3 (`threats.db`)
  - Purpose: Stores threat intelligence indicators indexed by IP address
  - Connection: Via `database/sql` with `mattn/go-sqlite3` driver v1.14.17
  - Tables: `ips` (IP addresses with category FK), `categories` (threat categories)
  - Client: Standard Go database/sql package
  - Initialization: `helpers/threatIntel.go` (OpenDBConnection, BuildDB, UpdateDB functions)
  - File location: Current working directory or specified path
  - Size with datacenter ASNs: ~7GB (optional, flag `-includedc`)
  - Usage: Queried during enrichment for IP threat matches via SQL queries

**MaxMind MMDB Files:**
- GeoLite2-ASN.mmdb, GeoLite2-City.mmdb, GeoLite2-Country.mmdb
  - Format: MaxMind MMDB binary format
  - Storage: File system (default CWD or `-dbdir` specified directory)
  - Access: Via oschwald/maxminddb-golang library
  - Auto-download: Triggered if files not found or `-updategeo` flag specified
  - Implementation: `helpers/maxmind.go`

**File Storage:**
- Local filesystem only
  - Input logs: Directory specified via `-logdir` flag (default: `input`)
  - Output enriched CSVs: Directory specified via `-outputdir` flag (default: `output`)
  - Cache files: Local directory (dns.cache, whois.cache, idb.cache - 1GB each)
  - Threat database: Local SQLite file (threats.db)

**Caching:**
- VictoriaMetrics/fastcache v1.12.1 - In-memory caching with file persistence
  - DNS cache: `dns.cache` (1GB max) - Caches reverse DNS lookups
  - WHOIS cache: `whois.cache` (1GB max) - Caches WHOIS query results for IPs and domains
  - InternetDB cache: `idb.cache` (1GB max) - Caches Shodan InternetDB responses
  - Implementation: `helpers/network.go` and `helpers/threatIntel.go`
  - Variables: `vars.Dnsfastcache`, `vars.Whoisfastcache`, `vars.IDBfastcache` in `vars/vars.go`

## Authentication & Identity

**Auth Provider:**
- Custom authentication for MaxMind API
  - Implementation: Basic authentication in `helpers/network.go` (DownloadAuthenticatedFile function)
  - Format: MaxMind API key split as `accountid:apikey` for HTTP Basic Auth
  - Env var lookup: `MM_API` environment variable or `mm_api.txt` file fallback
  - No OAuth/token-based auth required

**API Keys Required:**
- MaxMind API Key (required for database downloads): Format `ACCOUNTID:APIKEY`
- Shodan API (optional, free tier available): No explicit key needed for basic InternetDB queries
- Other feed sources: Public feeds, no authentication required

## Monitoring & Observability

**Error Tracking:**
- Not detected - No external error tracking service integration (Sentry, DataDog, etc.)
- Local application errors logged via rs/zerolog

**Logs:**
- rs/zerolog structured logging to stdout and `logboost.log` file
  - Log levels: Error, Info, Debug messages throughout codebase
  - Format: JSON structured logs from zerolog
  - File location: `logboost.log` defined in `vars/vars.go`

## CI/CD & Deployment

**Hosting:**
- Not applicable - Command-line utility (standalone executable)
- Deployment: Download compiled binary from GitHub releases or build locally via `go build`

**CI Pipeline:**
- Not detected - No GitHub Actions or CI/CD configuration visible

**Build Instructions:**
- Go compilation: `go build` from project root produces platform-specific binary
- Cross-compilation: Not yet supported (TODOs in code for cross-platform path handling)

## Environment Configuration

**Required env vars:**
- `MM_API` - MaxMind API key (format: `ACCOUNTID:APIKEY`)
  - Fallback: File `mm_api.txt` in current working directory
  - Fallback: Command-line flag `-api`

**Optional env vars:**
- None detected for other services (all other config via command-line flags)

**Secrets location:**
- MaxMind API key: Environment variable `MM_API` (recommended)
- Alternative: `mm_api.txt` file in current working directory (less secure)
- Alternative: Command-line flag `-api` (visible in process list, least secure)

**Command-line Configuration:**
- Comprehensive flag-based configuration in `main.go` parseArgs function
  - Log parsing: `-logdir`, `-outputdir`, `-convert`, `-getall`, `-regex`
  - Geolocation: `-api`, `-dbdir`, `-updategeo`
  - Threat intelligence: `-buildti`, `-updateti`, `-useti`, `-intelfile`, `-intelname`, `-inteltype`
  - DNS enrichment: `-dns`
  - WHOIS enrichment: `-whois`
  - Shodan InternetDB: `-idb`
  - Date filtering: `-startdate`, `-enddate`, `-datecol`, `-dateformat`
  - Performance: `-maxgoperfile`, `-batchsize`, `-writebuffer`, `-concurrentfiles`
  - Format conversion: `-separator`, `-delimiter`, `-jsoncol`, `-ipcol`, `-rawtxt`, `-fullparse`
  - Output: `-combine`, `-passthrough`

## Webhooks & Callbacks

**Incoming:**
- Not detected - No webhook endpoints or HTTP server functionality

**Outgoing:**
- Not detected - No callback or webhook implementation
- Unidirectional: Application pulls data from external sources (MaxMind, threat feeds, Shodan)

## Network Dependencies

**Required Connectivity:**
- MaxMind: `https://download.maxmind.com` (database downloads)
- Threat feeds: Multiple domains in `feed_config.json` (HTTP/HTTPS downloads)
- DNS resolution: Cloudflare 1.1.1.1:53 (configured in `helpers/network.go` resolver)
- WHOIS: `whois.iana.org:43` and referral WHOIS servers (via TCP port 43)
- Shodan InternetDB: `https://api.shodan.io` (via HTTP client with 2-second timeout)

**Port Requirements:**
- 443 - HTTPS for MaxMind and threat feed downloads
- 80 - HTTP for some threat feeds (e.g., cinsscore.com)
- 53 - DNS queries (UDP to 1.1.1.1)
- 43 - WHOIS protocol (TCP to various WHOIS servers)

---

*Integration audit: 2026-02-05*
