# Technology Stack

**Analysis Date:** 2026-02-05

## Languages

**Primary:**
- Go 1.20 - Complete application implementation in `main.go`, `helpers/`, `parsers/`, and module packages

**Secondary:**
- JSON - Configuration and data interchange (feed_config.json)

## Runtime

**Environment:**
- Go 1.20 runtime
- Windows and Linux compatible (with noted TODO for cross-platform path handling)

**Package Manager:**
- Go Modules - Defined in `go.mod` with lockfile `go.sum`

## Frameworks

**Core:**
- Standard Go library (net, database/sql, encoding/json, flag, io/fs, os, path/filepath, strings, sync, time, context)

**Logging:**
- rs/zerolog v1.31.0 - Structured logging framework, instantiated in `main.go` and used throughout helpers

**Database:**
- database/sql (stdlib) - SQLite database interface
- mattn/go-sqlite3 v1.14.17 - SQLite3 driver for Go

**Geolocation:**
- oschwald/maxminddb-golang v1.12.0 - MaxMind MMDB file parsing for GeoLite2 databases

**Caching:**
- VictoriaMetrics/fastcache v1.12.1 - In-memory caching for DNS, WHOIS, and Shodan InternetDB results
- allegro/bigcache/v3 v3.1.0 - Secondary caching option
- cespare/xxhash/v2 v2.2.0 - Hash function for caching keys

**Compression:**
- golang/snappy v0.0.4 - Snappy compression for tar.gz archive handling in `helpers/maxmind.go`

**Platform Support:**
- spf13/afero v1.10.0 - File system abstraction
- golang.org/x/sys v0.12.0 - Cross-platform system calls
- golang.org/x/text v0.3.7 - Text encoding utilities
- mattn/go-colorable v0.1.13 - Colored terminal output support
- mattn/go-isatty v0.0.19 - Terminal detection

**WHOIS:**
- golang.org/x/net/proxy - Custom WHOIS client implementation in `helpers/whois.go` for domain and IP lookups

## Key Dependencies

**Critical:**
- rs/zerolog v1.31.0 - Structured logging used throughout application for error handling, info messages, and debug output
- oschwald/maxminddb-golang v1.12.0 - IP geolocation enrichment (ASN, Country, City data from MaxMind GeoLite2 databases)
- mattn/go-sqlite3 v1.14.17 - Threat intelligence database storage and querying

**Infrastructure:**
- VictoriaMetrics/fastcache v1.12.1 - Caching for DNS lookups, WHOIS results, and Shodan InternetDB to reduce network calls and improve performance
- golang.org/x/net/proxy - WHOIS lookups for IP addresses and domains with configurable timeout and referral handling

## Configuration

**Environment:**
- MaxMind API Key: Loaded via environment variable `MM_API`, fallback to file `mm_api.txt`, or command-line flag `-api`
- Multiple cache files: `dns.cache`, `whois.cache`, `idb.cache` (1GB max size each)
- Threat database: `threats.db` (SQLite3)
- Configuration: `feed_config.json` - Defines threat intelligence feeds with URLs and categories

**Build:**
- go.mod: Module definition with Go 1.20 requirement
- go.sum: Dependency lock file (presence verified)
- Standard Go toolchain: `go build`, `go test`, `go run` commands

## Platform Requirements

**Development:**
- Go 1.20 or higher
- Windows or Linux (cross-platform support noted in TODOs but not yet implemented)
- MaxMind account for free GeoLite2 API credentials (https://www.maxmind.com/en/geolite2/signup)
- Text editor or IDE supporting Go

**Production:**
- Compiled Go binary (Windows `.exe` or Linux executable)
- Network connectivity for:
  - MaxMind GeoLite2 database downloads (https://download.maxmind.com)
  - Threat intelligence feed downloads (multiple sources in feed_config.json)
  - DNS queries (via Cloudflare 1.1.1.1 resolver by default)
  - WHOIS queries (port 43 to whois.iana.org and referral servers)
  - Shodan InternetDB API (api.shodan.io)
- Disk space for:
  - Compiled binary
  - MaxMind MMDB files (ASN, City, Country - typically <100MB total)
  - SQLite threat database (variable size, ~7GB with datacenter ASNs included)
  - Cache files (1GB each: dns.cache, whois.cache, idb.cache)
  - Input log directory and output CSV directory (size depends on log volume)

---

*Stack analysis: 2026-02-05*
