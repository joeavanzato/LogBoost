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
  * Generic Syslog
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

-logdir [string] (default="input") - specify the directory containing one or more CSV files to process
-outputdir [string] (default="output") - specify the directory to store enriched logs - defaults to $CWD\output

-ipcol [string] (default="IP address") - specify the name of a column in the CSV files that stores IP addresses - defaults to 'IP address' to find Azure Signin Data column
-jsoncol [string] (default="AuditData") - specify the name of a column in the CSV files storing Azure Audit JSON blobs - defaults to 'AuditData'
-flatten [bool] (default=false) - [TODO] - flatten a nested JSON structure into a CSV

-regex [bool] (default=false) - Scan each line for first IP address matche via regex rather than specifying a specific column name.

-convert [bool] (default=false) - Tells log2geo to look for .log/.txt files in the specified log directory in addition to CSV then attempts to read them in one of a few ways
  - IIS - Looks for #Fields and comma-delimited values
  - W3C - Looks for #Fields and space-delimited values
  - KV - [TODO] Looks for KV-style logging based on provided -delimiter and -separator values
-rawtxt [bool] - Handle any identified .txt/.log file as raw text if parser is not identified - should be used with -convert.
-fullparse [bool] - Specify to perform 'deep' key detection on file formats with variable columns such as CEF, JSON, etc - will increase processing time since we have to read the whole file twice basically.
 
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
log2geo.exe -buildti -useti -logdir C:\logs -dns -ipcol ipaddress : Downloaded the threat feeds listed in feed_config.json, parse into a SQLite DB and use when enriching the target CSV column 'ipaddress' along with live-querying domain names associated with the IP address.
log2geo.exe -logdir logs -dns -maxgoperfile 20 -batchsize 100 : Process each file with up to 20 goroutines handling 100 lines per routine (20,000 concurrently) and also enrich detected IP addresses with DNS lookups
log2geo.exe -logdir C:\azureadlogs -outputdir enriched_logs : Look for all CSVs in directory 'C:\azureadlogs', output logs to 'enriched_logs' and use defaults for IP/JSON columns that may contain IP addresses (Azure Log Exports)
log2geo.exe -logdir somelogs -ipcol "IPADDRESS" : Look for all CSVs in directory 'somelogs' and subsequently enrich based on column-named 'IPADDRESS'
log2geo.exe -logdir logs -convert : log2geo will also hunt for .log/.txt files that can be converted to CSV (IIS, W3C)
log2geo.exe -logdir C:\logging -maxgoperfile 30 -batchsize 1000 -convert -concurrentfiles 100 : Identify all .csv, .txt and .log files in C:\logging and process 100 files concurrently reading 1000 lines at a time split between 30 goroutines per file.
log2geo.exe -logdir logs -updateti -useti -batchsize 1000 -maxgoperfile 40 -concurrentfiles 5000 -regex  -combine : Update and use threat intelligence to process CSVs from "logs" dir using the specified concurrency settings, combining final outputs and using regex to find the appropriate IP address to enrich on a line-by-line basis.
log2geo.exe  -convert -logdir iislogs -startdate 01/01/2023 -datecol date -dateformat 2006-01-02 -convert -enddate 01/04/2023 : Parse and Convert IIS logs with a date record between 1/1/23 and 1/4/23 (inclusive)
```

### Threat Intelligence Notes
log2geo is capable of downloading and normalizing configurable text-based threat intelligence feeds to a single SQLite DB and using this DB to enrich records during processing based on the 'type' of intelligence it was ingested as.

Over 40 opensource feeds are included by default - when the 'buildti' flag is used, the database is initialized for the first time - this is only required once.  Subsequently, the 'updateti' flag can be used to download fresh copies of intelligence and ingest it into the existing databnase - old data is **not** deleted and IPs are treated as a unique column.  Therefore, an IP will only exist based on the first type/url that it is ingested as.  This is not designed to be a TIP but rather a quick reference for hunting suspicious activity in logs.

Include the 'useti' flag to actually use the database during enrichment processes - there is a minor efficiency hit but it is typically negligble.

Adding custom files to the underlying database can be achieved using the -intelfile and -inteltype flags together.


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