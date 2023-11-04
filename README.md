# log2geo
 
log2geo is a command-line utility originally designed to enrich IP addresses in CSV files with ASN, Country and City information provided by the freely available MaxMind GeoLite2 DBs.  

While at first built to support Azure exports, it is possible to use this to enrich any type of text-based data containing an IP address with parsing support built-in for a number of file types such as IIS, W3C, ELF, CEF and CLF as well as the capability to simple parse entire lines of raw text, which makes it capable of handling any type of text-based data.

In addition to parsing CSV data, log2geo can also convert a limited number of other log-formats to CSV, currently including IIS and W3C formats - generic KV log breaking is being worked on.

log2geo can also perform reverse lookups on each unique IP address detected in the source files to identify related domains.  

On top of this, it is possible to pull down text-based threat intelligence and parse these into a local SQLite DB which is then used to further enrich detected IP addresses with the 'type' provided in feed_config.json of the intel.

All in - log2geo can add Country, City, ASN, ThreatCategory and live Domains to structured data (CSV/IIS/W3C) as well as unstructured data (raw logs, syslog, etc) using regex or known column names.

### Additional Features
* Input File Types that can be processed to a structured CSV
  * CSV
  * Internet Information Services (IIS)
  * W3C Extended Format (W3C)
  * Extended Log Format (ELF)
  * Common Log Format / Combined Log Format (CLF)
  * Common Event Format (CEF)
  * JSON per-line logging
  * Generic Syslog
* Read files from plain-text version or GZ archive (linux logs, etc)
* Parsing raw text files to extract and enrich detected IP address
* Filtering outputs on specific date ranges
* Enriching with MaxMind Geo/ASN Information
* Enriching with DNS lookups
* Enriching with configurable threat intelligence feeds
* Ingesting custom intelligence files for downstream use
* Combining outputs on per-directory basis
* Customizing concurrency settings to fine-tune efficiency/throughput
* Capable of handling thousands of files concurrently by default
* Auto-download / update of MaxMind and configured Threat Intelligence


### Requirements

To use this tool, a free API key from MaxMind is required - once an account is registered, a personal license key can be generated at https://www.maxmind.com/en/accounts/668938/license-key.

This license key must be provided in one of 3 ways to the tool:
* via commandline argument '-api'
* via environment variable 'MM_API'
* via file in current working directory named 'mm_api.txt'

The tool will automatically download and extract the latest version of each database if they are not found in the current working directory.

### Commandline Arguments
```
-dbdir [string] (default="") - Specify the directory containing MaxMind DBs at the dir or one level below - if they don't exist, will attempt to download.

-api [string] (default="") - Specify a MaxMind API key - if not provided will subsequently check for ENVVAR 'MM_API' then mm_api.txt in CWD.

-logdir [string] (default="input") - specify the directory containing one or more files to process
-outputdir [string] (default="output") - specify the directory to store enriched logs - defaults to $CWD\output

-ipcol [string] (default="IP address") - specify the name of a column in the CSV files that stores IP addresses - defaults to 'IP address' to find Azure Signin Data column
-jsoncol [string] (default="AuditData") - specify the name of a column in the CSV files storing Azure Audit JSON blobs - defaults to 'AuditData'

-regex [bool] (default=false) - Scan each line for first IP address matche via regex rather than specifying a specific column name.

-convert [bool] (default=false) - Tells log2geo to look for .log/.txt files in the specified log directory in addition to CSV then attempts to read them in one of a few ways
  - IIS - Looks for #Fields and comma-delimited values
  - W3C - Looks for #Fields and space-delimited values
  - KV - [TODO] Looks for KV-style logging based on provided -delimiter and -separator values
-rawtxt [bool] - Handle any identified .txt/.log file as raw text if parser is not identified - should be used with -convert.
-fullparse [bool] - Specify to perform 'deep' key detection on file formats with variable columns such as CSVs with JSON Blobs, CEF, JSON, etc - will increase processing time since we have to read the whole file twice basically.
 
-separator [string] (default="=") - [TODO] Used when -convert is specified and a file cannot be identified as IIS/W3C/CSV
-delimiter [string] (default=" ") - [TODO] Used when -convert is specified and a file cannot be identified as IIS/W3C/CSV

-dns [bool] (default=false) - Tell log2geo to perform reverse-lookups on detected IP addresses to find currently associated domains.
 
-maxgoperfile [int] (default=20) - Limit number of goroutines spawned per file for concurrent chunk processing
-batchsize [int] (default=500) - Limit how many lines per-file are sent to each spawned goroutine
-writebuffer [int] (default=2000) - How many lines to buffer in memory before writing to CSV
-concurrentfiles [int] (default=100) - Limit how many files are processed concurrently.

-combine [bool] (default=false) - Combine all files in each output directory into a single CSV per-directory - this will not work if the files do not share the same header sequence/number of columns.

-buildti [bool] (default=false) - Build the threat intelligence database based on feed_config.json
-updateti [bool] (default=false) - Update (and build if it doesn't exist) the threat intelligence database based on feed_config.json
-useti [bool] (default=false) - Use the threat intelligence database if it exists
-intelfile [string] - Specify the path to an intelligence file to ingest into the threat DB (must use with -inteltype)
-inteltype [string] - Specify the type to appear when there is a match on custom-ingested ingelligence (must use with -intelfile)
-summarizeti [bool] - Summarize the existing threat database

-startdate [string] - Start date of data to parse - defaults to year 1800.  Can be used with or without enddate.
-enddate [string] - End date of data to parse - defaults to year 2300.  Can be used with or without startdate.
-datecol [string] - Name of the column/header that contains the date to parse.  Must be provided with startdate/enddate.  Will check for either full equality or if the scanned column name contains the provided string - so be specific.
-dateformat [string] - Provide the format of the datecol data in golang style ("2006-01-02T15:04:05Z") - rearrange as appropriate (see example). Must be provided with startdate/enddate.

-getall [bool] - Look for any file in input directory and process as raw text if a parser is not identified - similar to '-rawtxt -convert' but also gets files without extensions or files that do not have .txt/.log extension.
```

### Example Usage
```
log2geo.exe -logdir logs -api XXX
log2geo.exe -buildti : Initialize/build the indicator database - should only be required once to build threats.db
log2geo.exe -updateti : Use to download and ingest indicator feed updates
log2geo.exe -logdir C:\logs -dns -useti -ipcol ipaddress : Parse the logs present in C:\logs and, use DNS to lookup domains on detected IPs and also use the indicator database - look for IPs in column named 'ipaddress'
log2geo.exe -logdir logs -dns -maxgoperfile 40 -batchsize 100 -writebuffer 2000 : Process each file with up to 40 goroutines handling 100 lines per routine and buffering 2000 records before writing to disk - also enrich detected IP addresses with DNS lookups
log2geo.exe -logdir C:\azureadlogs -outputdir enriched_logs : Look for all CSVs in directory 'C:\azureadlogs', output logs to 'enriched_logs' and use defaults for IP/JSON columns that may contain IP addresses (Azure Log Exports)
log2geo.exe -logdir somelogs -ipcol "IPADDRESS" : Look for all CSVs in directory 'somelogs' and subsequently enrich based on column-named 'IPADDRESS'
log2geo.exe -logdir logs -convert : log2geo will also hunt for .log/.txt files that can be converted to CSV (IIS, W3C)
log2geo.exe -logdir C:\logging -maxgoperfile 30 -batchsize 1000 -convert -concurrentfiles 100 : Identify all .csv, .txt and .log files in C:\logging and process 100 files concurrently reading 1000 lines at a time split between 30 goroutines per file.
log2geo.exe -logdir logs -updateti -useti -batchsize 1000 -maxgoperfile 40 -concurrentfiles 5000 -regex  -combine : Update and use threat intelligence to process CSVs from "logs" dir using the specified concurrency settings, combining final outputs and using regex to find the appropriate IP address to enrich on a line-by-line basis.
log2geo.exe  -convert -logdir iislogs -startdate 01/01/2023 -datecol date -dateformat 2006-01-02 -convert -enddate 01/04/2023 : Parse and Convert IIS logs with a date record between 1/1/23 and 1/4/23 (inclusive)
```

### Threat Intelligence Notes
log2geo is capable of downloading and normalizing configurable text-based threat indicator feeds to a single SQLite DB and using this DB to enrich records during processing based on the 'type' of intelligence it was ingested as.

Over 90 opensource feeds are included by default - when the 'buildti' flag is used, the database is initialized for the first time - this is only required once.  Subsequently, the 'updateti' flag can be used to download fresh copies of intelligence and ingest it into the existing databnase - old data is **not** deleted and IPs are treated as a unique column.  Therefore, an IP will only exist based on the first type/url that it is ingested as.  This is not designed to be a TIP but rather a quick reference for hunting suspicious activity in logs.

Include the 'useti' flag to actually use the database during enrichment processes - there is a minor efficiency hit but it is typically negligble - if only geolocation is required, then there is no need to use this feature.

Adding custom text-based files to the underlying database can be achieved using the -intelfile and -inteltype flags together.

### TODOs
* Add capability to 'flatten' JSON columns embedded within a CSV
* Add JSON-logging parse capabilities 
* Add KV parsing capabilities
* Add ability to specify multiple IP address column names when processing a variety of log types simultaneously.
* Export inline to parquet instead of CSV

### Performance Considerations
log2geo is capable of processing a large amount of data as all file processing is handled in separate goroutines - this means if you point it at a source directory containing 10,000 files, it is possible to spawn 10,000 individual goroutines depending on the -concurrentfiles setting.  Additionally, the 'maxgoperfile' argument controls how many sub-routines are spawned to handle the batches for each individual file - therefore, if you had this set to 1, you would have 10k goroutines spawned at any given time - if you used 20 as is default, there would be upwards of 200,000 goroutines spawned assuming all file processing happened concurrently. 

Realistically, this should not cause any issues on most modern machines - a machine with 4 GB of RAM is capable of easily handling ~1,000,000 goroutines - but now we have to take into account the files we are processing - this is where batchsize becomes important.  We must select a batchsize that is appropriate to both the data we are treating as well as the machine we are operating on - the defaults are typically good starting points to ensure work is processed efficiently but should be played with if performance is poor.

Additionally, the -concurrentfiles flag can be used to limit the number of files processed concurrently - this defaults to 100 - together with -batchsize and -maxgoperfile the user can tweak the various concurrency settings associated with file processing to ensure performance and memory usage are suitable to the task and system at hand.

On top of this - as lines are sent to the main writer for each output file, they are buffered into a slice before writing to file to help improve throughput - the amount of lines buffered at a time for each output file can be controlled via the -writebuffer parameter - defaulting to 1000.

### Handling Different Log Types

#### CSV
Handling CSV input is straight forward:
1. Point log2geo at the logs via '-logdir'
2. Either tell log2geo which column contains an IP address with '-ipcol' or use '-regex' to have it scan each line for the first non-private IP address
3. That's it - you can use additional settings if desired such as '-dns', '-useti' or the date filtering flags but this is enough for basic processing of standard CSVs.
```
log2geo.exe -logdir C:\csvfiles
```
If we are processing a directory that contains time-delimited files, it may be useful to also include '-combine' to push similar files together in each output directory.
```
log2geo.exe -logdir C:\csvfiles -combine
```

#### IIS/W3C/ELF/CLF (Web Server Style Logging)
1. Tell log2geo where to find the logs via '-logdir'
2. Include the '-convert' flag so we find files besides .csv
3. At the core - that is all that is required - if you are processing directories that contain similar files, it may also be useful to include '-combine' to combine the outputs.
4. Optional flags such as -dns, -useti and the date filtering can also be used if desired.
```
log2geo.exe -logdir C:\inetpub\logs -convert -combine
```

#### Common Event Format (CEF)
Handling is similar to above - since these are typically not CSV files, we need to use '-convert' flag to find/parse them.

log2geo is currently capable of detecting/parsing 4 types of CEF input, with line samples provided below:
* CEF with syslog RFC 3164 Header
  * <6>Sep 14 14:12:51 10.1.1.143 CEF:0|.....
* CEF with syslog RFC 5424 Header
  * <34>1 2003-10-11T22:14:15.003Z mymachine.example.com CEF:0|.....
* CEF with a generic syslog Header
  * Jun 27 18:19:37 ip-172-31-82-74 systemd[1]: CEF:0|.....
* CEF without any prefixes/headers
  * CEF:0|.....

Additionally, log2geo is capable of parsing out all possible K=V extensions in a given file and using these as column headers, in effect 'flattening' the CEF extensions for easier filtering.  This can be enabled via the '-fullparse' flag - this will increase processing time as we need to read the file twice - once to gather all possible headers and again to actually parse it.

#### Generic Syslog
Nothing special required here - similar to IIS/CEF/etc, just specify your log directory and use '-convert' - but since syslog and similar files normally do not have an extension, make sure to also use '-getall' - this flag makes log2geo try to process any type of file in the log directory, not just .csv, .txt or .log.

By defaut, log2geo can parse generic syslog, RFC5424 and RFC3164, with examples of each provided below.
* Generic
  * Jun 27 18:19:37 ip-172-31-82-74 systemd[1]: MESSAGE
  * Jun 27 18:17:39 ip-172-31-82-74 sudo: MESSAGE
* RFC 5424
* <34>1 2003-10-11T22:14:15.003Z mymachine.example.com MESSAGE
* RFC 3164
  * <6>Sep 14 14:12:51 10.1.1.143 MESSAGE

#### Any other Text-based files
While log2geo may not have parsers for every type of log or file-type - it can still help analysts quickly enrich any file type by using regex to find the first non-private IP address in each line of a file and enriching appropriately.

```
log2geo.exe -logdir C:\somelogs -convert -rawtxt
```
Each line of the input file will be included in it's entirety in the first column of the resulting CSV with additional columns added for the log2geo enrichments.

#### References
This section lists any pages, articles or other content used during the building or execution of this tool.
* https://www.maxmind.com/en/home
* https://github.com/korylprince/ipnetgen
* https://github.com/rs/zerolog
* https://github.com/mattn/go-sqlite3
* https://stackoverflow.com/questions/28309988/how-to-read-from-either-gzip-or-plain-text-reader-in-golang/28332019#28332019

#### Included Indicator Feeds
* https://www.binarydefense.com/banlist.txt
* https://blacklist.3coresec.net/lists/http.txt
* https://lists.blocklist.de/lists/bruteforcelogin.txt
* https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt
* https://rules.emergingthreats.net/blockrules/compromised-ips.txt
* https://threatview.io/Downloads/IP-High-Confidence-Feed.txt
* https://blacklist.3coresec.net/lists/ssh.txt
* https://dataplane.org/signals/sshidpw.txt
* https://threatview.io/Downloads/Experimental-IOC-Tweets.txt
* https://iplists.firehol.org/files/xroxy_30d.ipset
* https://blacklist.3coresec.net/lists/misc.txt
* https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt
* https://iplists.firehol.org/files/cleantalk_30d.ipset
* https://iplists.firehol.org/files/stopforumspam_90d.ipset
* https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv
* https://iplists.firehol.org/files/php_spammers_30d.ipset
* https://iplists.firehol.org/files/cybercrime.ipset
* https://dataplane.org/signals/sshclient.txt
* https://dataplane.org/signals/vncrfb.txt
* https://iplists.firehol.org/files/tor_exits_30d.ipset
* https://iplists.firehol.org/files/dm_tor.ipset
* https://iplists.firehol.org/files/php_harvesters_30d.ipset
* https://iplists.firehol.org/files/bds_atif.ipset
* https://iplists.firehol.org/files/vxvault.ipset
* https://iplists.firehol.org/files/botscout_30d.ipset
* https://lists.blocklist.de/lists/21.txt
* https://iplists.firehol.org/files/iblocklist_onion_router.netset
* https://iplists.firehol.org/files/proxylists_30d.ipset
* https://iplists.firehol.org/files/firehol_abusers_30d.netset
* https://iplists.firehol.org/files/greensnow.ipset
* https://iplists.firehol.org/files/ipblacklistcloud_recent_30d.ipset
* https://dataplane.org/signals/telnetlogin.txt
* https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst
* https://iplists.firehol.org/files/bitcoin_nodes_30d.ipset
* https://iplists.firehol.org/files/php_dictionary_30d.ipset
* https://kriskintel.com/feeds/ktip_malicious_Ips.txt
* https://lists.blocklist.de/lists/80.txt
* https://dataplane.org/signals/dnsrd.txt
* https://myip.ms/files/blacklist/htaccess/latest_blacklist.txt
* https://lists.blocklist.de/lists/22.txt
* https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/vpn/NordVPNIPs.csv
* https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/vpn/ProtonVPNIPs.csv
* https://www.talosintelligence.com/documents/ip-blacklist
* https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/month.csv
* https://reputation.alienvault.com/reputation.generic
* http://cinsscore.com/list/ci-badguys.txt
* https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt
* https://lists.blocklist.de/lists/25.txt
* https://iplists.firehol.org/files/et_compromised.ipset
* https://iplists.firehol.org/files/sslproxies_30d.ipset
* https://www.botvrij.eu/data/ioclist.ip-src
* https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-nodes.lst
* https://raw.githubusercontent.com/scriptzteam/badIPS/main/ips.txt
* https://reputation.alienvault.com/reputation.data
* https://iplists.firehol.org/files/blocklist_net_ua.ipset
* https://raw.githubusercontent.com/rodanmaharjan/ThreatIntelligence/main/Mirai.txt
* https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt
* https://osint.digitalside.it/Threat-Intel/lists/latestips.txt
* https://www.dan.me.uk/torlist/
* https://threatfox.abuse.ch/export/csv/ip-port/recent/
* https://charles.the-haleys.org/ssh_dico_attack_with_timestamps.php?days=30
* http://sekuripy.hr/blacklist.txt
* https://lists.blocklist.de/lists/993.txt
* https://cdn.ellio.tech/community-feed
* https://iplists.firehol.org/files/tor_exits_30d.ipset
* https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.txt
* https://www.botvrij.eu/data/ioclist.ip-dst
* https://iplists.firehol.org/files/et_compromised.ipset
* https://check.torproject.org/torbulkexitlist
* https://lists.blocklist.de/lists/110.txt
* https://iplists.firehol.org/files/firehol_webclient.netset
* https://iplists.firehol.org/files/proxz_30d.ipset
* https://danger.rulez.sk/projects/bruteforceblocker/blist.php
* https://iplists.firehol.org/files/socks_proxy_30d.ipset
* https://dataplane.org/signals/sshpwauth.txt
* https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/unverified/IPC2s-30day.csv
* https://lists.blocklist.de/lists/443.txt
* https://lists.blocklist.de/lists/143.txt
* https://dataplane.org/signals/dnstcp.txt
* https://iplists.firehol.org/files/dyndns_ponmocup.ipset
* https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt
* https://github.com/rodanmaharjan/ThreatIntelligence/raw/main/blackcat%20ransomware.txt
* https://beesting.tools/
* https://github.com/rodanmaharjan/ThreatIntelligence/raw/main/CobaltStrike.txt
* https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv
* https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/compromised-ips.txt
* https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/illuminate.txt
* https://github.com/rodanmaharjan/ThreatIntelligence/raw/main/Malicious%20IP.txt
* https://lists.blocklist.de/lists/bots.txt
* https://mirai.security.gives/data/ip_list.txt
* https://www.darklist.de/raw.php
* https://report.rutgers.edu/DROP/attackers
* https://iplists.firehol.org/files/et_tor.ipset
* https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/master/sans.txt
* https://iplists.firehol.org/files/firehol_proxies.netset
* https://github.com/rodanmaharjan/ThreatIntelligence/raw/main/C2%20IOC.txt
* https://dataplane.org/signals/proto41.txt
* https://raw.githubusercontent.com/elliotwutingfeng/rstthreatsall/main/ioc_ip_short_all.txt