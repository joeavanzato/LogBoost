
<p align="center">
<img src="images/logo.png">
</p>
<h1 align="center">LogBoost</h1>

### What is it?

LogBoost is a command-line utility originally designed to enrich IP addresses in CSV files with ASN, Country and City information provided by the freely available MaxMind GeoLite2 DBs.  

LogBoost can parse and convert a variety of structured and semi-structured log formats to CSV while simultaneously enriching detected IP addresses, including JSON, IIS, W3C, ELF, CLF, CEF, KV, SYSLOG.

The tool can also perform reverse lookups on each IP address detected in the source files to identify currently related domains.  If 'GeoLite2-Domain.mmdb' is detected in the specified MaxMind DB Dir (CWD by default), the associated TLD of the enriched IP address is provided in the output as well.

On top of this, LogBoost can download text-based threat intelligence as configured in feed_config.json and parse these into a local SQLite DB which is then used to further enrich detected IP addresses with indicator matches.

Additionally, LogBoost is capable of live querying both WhoIs servers for IP addresses/Domains as well as Shodan InternetDB to provide additional enrichment detail for analysts.

All in - LogBoost can convert a variety of log formats to CSV while enriching IP addresses with ASN Org/Number, Country, City, Domains and Indicator Match Information.

**Wiki: https://github.com/joeavanzato/LogBoost/wiki**

**QuickStart: https://github.com/joeavanzato/LogBoost/wiki/Quick-Start-Guide**

### Common Use Cases
* Enriching and combining a log directory containing thousands of similarly-structured files (WebServer logs, Cloudtrail dumps, Firewall exports, etc)
* Converting JSON Lines/Multi-line JSON blobs into more easily filterable CSVs 
* Parsing KV-pair logging, such as Firewall dumps (k1=v1,k2=v2, etc)
* Parsing CEF-style logging, from Syslog or otherwise, into CSV
* Finding suspicious IP addresses in any inspected file through threat indicator matching
* Enriching IP addresses to find associated domain names and geolocations in any inspected file


### Example Usage

To use, just download the latest release binary (along with feed_config.json if you wish to enhance results with threat intelligence.  Additionally, setup a free MaxMind account at https://www.maxmind.com/en/geolite2/signup?utm_source=kb&utm_medium=kb-link&utm_campaign=kb-create-account to get a license key for the free GeoLite2 Databases.  Once that key is acquired, you can either put it in an environment variable (MM_API), put it in a file in the CWD (mm_api.txt) or provide it at the command-line via the flag '-api'.

#### Common Use
* ```LogBoost.exe -buildti``` - Build the Threat Indicator database locally - will also update all configured feeds.
* ```LogBoost.exe -updateti``` - Update the Threat Indicator database - run periodically to ingest new indicators from configured feeds.
* ```LogBoost.exe -updateti -includedc``` - Update the Threat Indicator database and also include datacenter IP addresses - this will add approximately ~129 million IPs consuming approximately 7 GB of space on disk.  This is typically not necessary as LogBoost also contains a built-in list of ASN Numbers derived from https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt
* ```LogBoost.exe -logdir logs -regex -api XXX``` - Enrich a directory containing one or more CSV files with Geolocation information, using regex to find the first non-private IP address in each row

* ```LogBoost.exe -useti -dns -whois -idb -getall -convert -regex``` - Enrich any files inside /input with Threat Intelligence, DNS, WhoIS, InternetDB and MaxMind data 


* ```LogBoost.exe -logdir input -jsoncol data -ipcol client -fullparse``` - Enrich any CSV file within 'input' while also expanding JSON blobs located in the column named 'data' - the enriched IP address will be pulled from the column named 'client'.
* ```LogBoost.exe -logdir input -jsoncol data -fullparse -regex``` - Same as above but use regex to find the first non-private IP address.
* ```LogBoost.exe -logdir input -jsoncol data -fullparse -regex -useti``` - Same as above but also use the threat indicator db to enrich with IP matches.
* ```LogBoost.exe -logdir input -jsoncol data -fullparse -regex -useti -dns``` - Same as above but also do live DNS lookups on each IP address to find any associated domains.


* ```LogBoost.exe -logdir logs -convert -rawtxt``` - Process all .csv/.log/.txt files in 'logs' - look for relevant parsers or parse as raw text as last resort.
* ```LogBoost.exe -logdir logs -convert -getall``` - Process any file in 'logs', regardless of extension, with relevant parser or as raw text as last resort.


* ``` LogBoost.exe -logdir logs -maxgoperfile 40 -batchsize 100 -writebuffer 2000 -concurrentfiles 1000``` - Process up to 1k concurrent files with 40 'threads' per file, each thread handling 100 records and the writer for each output buffering 2000 records at a time.

* ```LogBoost.exe -logdir logs -convert -dns -useti -regex -combine ``` Look for all .csv/.log/.txt files inside 'logs' and enrich regexed IPs with Threat Indicators and DNS, combining all output files into a single CSV if a parser for the format is detected.

* ```LogBoost.exe  -convert -logdir iislogs -startdate 01/01/2023 -datecol date -dateformat 2006-01-02 -convert -enddate 01/04/2023``` - Parse and Convert logs storing date in a column/key named 'date' with a format as specified between the specified dates (inclusive ranging)

### Example Outputs
<h4 align="center">Enriching Azure Audit Log Export</h4>
<p align="center">
<img src="images/azure_audit_enrich.png">
</p>
<h4 align="center">Enriching and Expanding Azure Audit Log Export</h4>
<p align="center">
<img src="images/azure_audit_enrich_expand.png">
</p>
<h4 align="center">Enriching IPs with DNS (Live and MaxMind TLD if available)</h4>
<p align="center">
<img src="images/azure_audit_enrich_dns.png">
</p>
<h4 align="center">Enriching logs with built-in threat indicators</h4>
<p align="center">
<img src="images/azure_audit_enrich_ti.png">
</p>
<h4 align="center">Convert Common/Combined Log Format to CSV while enriching source IP address</h4>
<p align="center">
<img src="images/convert_CLF_logs.png">
</p>
<h4 align="center">Converting JSON Lines using Shallow or Deep Key parsing</h4>
<p align="center">
<img src="images/json_line_logging.png">
</p>
<h4 align="center">Parsing CloudTrail Multi-Line Records</h4>
<p align="center">
<img src="images/cloudtrail_parse.png">
</p>
<h4 align="center">Parsing arbitrary KV-style logs using provided separators/delimiters</h4>
<p align="center">
<img src="images/kv_firewall_logs.png">
</p>
<h4 align="center">Parsing Syslog (Generic/RFC 3164/RFC 5424) to CSV </h4>
<p align="center">
<img src="images/syslog_parsing.png">
</p>
<h4 align="center">Transparently handling GZ files</h4>
<p align="center">
<img src="images/gz_parsing.png">
</p>


### Primary Features
* Process Structured/Semi-Structured/Unstructured data to enriched CSV
  * CSV
  * Internet Information Services (IIS)
  * W3C Extended Format (W3C)
  * Extended Log Format (ELF)
  * Common Log Format / Combined Log Format (CLF)
  * Common Event Format (CEF)
    * Shallow or Deep Parsing
  * JSON per-line logging
    * Shallow or Deep Parsing
  * Multi-Line JSON Blobs from Fixed Inputs
    * AWS CloudTrail Exports
  * Generic Syslog
  * KV (key1=value1, key2="value 2") style logging
    * Shallow or Deep Parsing
  * Raw Text Files
* Read plain-text files or GZ archives transparently for all parser types
* Handles files 'line by line' to avoid reading entire file into memory
* Expand JSON blobs embedded within CSV to individual columns
* Filtering outputs on specific datetime ranges
* Enriching detected IP with MaxMind Geo/ASN Information
* Enriching detected IP with DNS lookups
* Enriching detected IP with configurable threat indicator feeds
* Enriching detected IP with WhoIs data
* Enriching detected IP with Shodan InternetDB data
* Enriching detected domain-names from DNS with WhoIs data
* Ingesting custom indicator files
* Combining outputs on per-directory basis
* Customizing concurrency settings to fine-tune efficiency/throughput
* Capable of handling thousands of files concurrently by default
* Auto-download / update of MaxMind and configured Threat Feeds


### Requirements

To use this tool, a free API key from MaxMind is required - once an account is registered, a personal license key can be generated at https://www.maxmind.com/en/accounts/.

In order to update MaxMind MMDBs, you must provide your Account ID and API Key in one of 3 ways to the tool:
* via commandline argument '-api'
* via environment variable 'MM_API'
* via file in current working directory named 'mm_api.txt'

The expected format is "$ACCOUNTID:$APIKEY" - for example, -api "222111:6ij3x2_GRChRSGRAWeHuFbu4W136UDGdrLeV_sse"

The tool will automatically download and extract the latest version of each database if they are not found in the current working directory.

Updates to local databases can be triggered via '-updategeo' flag.

### Outputs
The ultimate output of running LogBoost against one or more input files is a CSV file which represents the original data stream but will contain an additional 7 columns as listed below:
* lb_IP - Represents the IP address used for enrichment tasks.
* lb_ASN - Represents the name of the ASN Organization associated with the IP address.
* lb_ASN_Number - Represents the number of the ASN associated with the IP address
* lb_Country - Represents the name of the Country associated with the IP address.
* lb_City - Represents the name of the City associated with the IP address.
* lb_Domains (-dns) - Represents any domain name associated with the IP address, split by '|' if there are multiple.
* lb_TLD (-dns) - Represents the Top Level Domain associated with the IP address - only populated if 'GeoIP2-Domain.mmdb' is found in the specified MaxMind DB directory (CWD by default).
* lb_ThreatCategories (-useti) - Represents the threat categories associated with the IP address - will be a series of strings such as 'tor', 'proxy', etc separated by '|' or 'none' if it is not found in the database.
* lb_ThreatFeedCount (-useti) - Represents the number of unique threat feeds this IP address has been seen in.
* lb_ThreatFeeds (-useti) - Represents the actual feeds this IP address has been seen in - separated by '|'.
* lb_Domains - (-dns) - Represents domains that the IP resolves to.
* lb_TLD - (-dns) - Represents the hostname/TLD that  the IP resolves to (ex: aws.com)
* lb_DomainWhois_CreatedDate (-whois & -dns) - Represents the date that Whois reports for domain creation
* lb_DomainWhois_UpdatedDate (-whois & -dns) - Represents the date that Whois reports for domain update
* lb_DomainWhois_Country (-whois & -dns) - Represents the country that Whois reports for domain registration
* lb_DomainWhois_Organization (-whois & -dns) - Represents the organization that Whois reports for domain registration
* lb_IPWhois_CIDR (-whois) - Represents the CIDR network the IP address belongs to
* lb_IPWhois_NetName (-whois) - Represents the Network Name the IP address belongs to
* lb_IPWhois_NetType (-whois) - Represents the Network Type (Reallocated, etc) the IP address belongs to
* lb_IPWhois_Organization (-whois) - Represents the Organization Name the IP address belongs to
* lb_IPWhois_Created (-whois) - Represents the Created Date for the IP per Whois
* lb_IPWhois_Updated (-whois) - Represents the latest Updated Date for the IP per Whois
* lb_IPWhois_Country (-whois) - Represents the registration Country for the IP per Whois
* lb_IPWhois_Parent (-whois) - Represents the Parent Network for the IP per Whois
* lb_IDB_cpes (-idb) - Represents any known CPEs for the IP address
* lb_IDB_hostnames (-idb) - Represents any known hostnames for the IP address
* lb_IDB_ports (-idb) - Represents any known open ports
* lb_IDB_tags (-idb) - Represents any additional tagging details
* lb_IDB_vulns (-idb) - Represents any scanned/known vulnerabilities

### Commandline Arguments
```
-dbdir [string] (default="") - Specify the directory containing MaxMind DBs at the dir or one level below - if they don't exist, will attempt to download.
-updategeo [bool] (default=false) - Update local MaxMind DBs (if they already exist)

-api [string] (default="") - Specify a MaxMind API accountid/ke in format "$ID:$KEY" - if not provided will subsequently check for ENVVAR 'MM_API' then mm_api.txt in CWD.

-logdir [string] (default="input") - specify the directory containing one or more files to process
-outputdir [string] (default="output") - specify the directory to store enriched logs - defaults to $CWD\output

-ipcol [string] (default="IP address") - specify the name of a column in the CSV files that stores IP addresses - defaults to 'IP address' to find Azure Signin Data column
-jsoncol [string] (default="AuditData") - specify the name of a column in the CSV files storing Azure Audit JSON blobs - defaults to 'AuditData'

-regex [bool] (default=false) - Scan each line for first IP address matche via regex rather than specifying a specific column name.

-convert [bool] (default=false) - Tells LogBoost to look for .log/.txt files in the specified log directory in addition to CSV then attempts to read them in one of a few ways
-rawtxt [bool] - Handle any identified .txt/.log file as raw text if parser is not identified - should be used with -convert.
-fullparse [bool] - Specify to perform 'deep' key detection on file formats with variable columns such as CSVs with JSON Blobs, CEF, JSON, etc - will increase processing time since we have to read the whole file twice basically.
-getall [bool] - Look for any file in input directory and process as raw text if a parser is not identified - similar to '-rawtxt -convert' but also gets files without extensions or files that do not have .txt/.log extension.
 
-separator [string] (default="=") - Used when -convert is specified to try and parse kv style logging.  Example - if log is in format k1=v1,k2=v2 then the separator would be '='
-delimiter [string] (default=",") - Used when -convert is specified to try and parse kv style logging.  Example - if log is in format k1=v1,k2=v2 then the delimiter would be ','

-passthrough [bool] (default=false) - If specified, will skip any enrichment tasks and just convert input to CSV.

-dns [bool] (default=false) - Tell LogBoost to perform reverse-lookups on detected IP addresses to find currently associated domains.
 
-maxgoperfile [int] (default=20) - Limit number of goroutines spawned per file for concurrent chunk processing
-batchsize [int] (default=500) - Limit how many lines per-file are sent to each spawned goroutine
-writebuffer [int] (default=2000) - How many lines to buffer in memory before writing to CSV
-concurrentfiles [int] (default=100) - Limit how many files are processed concurrently.

-whois [bool] (default=false) - Enrich IP address (and domain if using -dns) with live WhoIs lookups

-idb [bool] (default=false) - Enrich IP address with live Shodan InternetDB data

-combine [bool] (default=false) - Combine all files in each output directory into a single CSV per-directory - this will not work if the files do not share the same header sequence/number of columns.

-buildti [bool] (default=false) - Build the threat intelligence database based on feed_config.json
-updateti [bool] (default=false) - Update (and build if it doesn't exist) the threat intelligence database based on feed_config.json
-includedc [bool] (default=false) - When using -updateti, if this is also specified LogBoost will download and expand a lsit of known DataCenter IP addresses for use in enrichment.
-useti [bool] (default=false) - Use the threat intelligence database if it exists
-intelfile [string] - Specify the path to an intelligence file to ingest into the threat DB (must use with -inteltype and -intelname)
-inteltype [string] - Specify the type to appear when there is a match on custom-ingested ingelligence (must use with -intelfile and -intelname)
-intelname [string] - Specify the name to appear when there is a match on custom-ingested ingelligence (must use with -intelfile and -inteltype)
-summarizeti [bool] - Summarize the existing threat database

-startdate [string] - Start date of data to parse - defaults to year 1800.  Can be used with or without enddate.
-enddate [string] - End date of data to parse - defaults to year 2300.  Can be used with or without startdate.
-datecol [string] - Name of the column/header that contains the date to parse.  Must be provided with startdate/enddate.  Will check for either full equality or if the scanned column name contains the provided string - so be specific.
-dateformat [string] - Provide the format of the datecol data in golang style ("2006-01-02T15:04:05Z") - rearrange as appropriate (see example). Must be provided with startdate/enddate.
```

### Threat Intelligence Notes
LogBoost is capable of downloading and normalizing configurable text-based threat indicator feeds to a single SQLite DB and using this DB to enrich records during processing based on the 'type' of intelligence it was ingested as.

Over 90 open-source feeds are included by default - when the 'buildti' flag is used, the database is initialized for the first time - this is only required once.  Subsequently, the 'updateti' flag can be used to download fresh copies of intelligence and ingest it into the existing database.  This is not designed to be a TIP but rather a quick reference for hunting suspicious activity in logs.  

When using '-updateti', if '-includedc' is used, an additional list of DataCenter IP addresses will be added to the DB - this will consume approximately ~7 GB of disk space and add ~129 million IP addresses.  This is typically not necessary since LogBoost also includes a list of ASN Numbers that correspond to datacenters as sourced from https://github.com/X4BNet/lists_vpn/blob/main/input/datacenter/ASN.txt which is used to determine if any particular IP address belongs to a datacenter.

Include the 'useti' flag to actually use the database during enrichment processes - there is a minor efficiency hit, but it is typically negligble - if only geolocation is required, then there is no need to use this feature.

Adding custom text-based files to the underlying database can be achieved using the -intelfile and -inteltype flags together.

**Included Indicator Feeds:** https://github.com/joeavanzato/LogBoost/wiki/Threat-Indicator-Feeds

### Feature TODOs
* Add ability to specify multiple IP address column names when processing a variety of log types simultaneously.
* Ensure there is no collision between embedded JSON keys and existing column names by re-mapping names.
* Maybe: Export inline to parquet/other data structures instead of CSV

### Performance Considerations
LogBoost is capable of processing a large amount of data as all file processing is handled in separate goroutines - this means if you point it at a source directory containing 10,000 files, it is possible to spawn 10,000 individual goroutines depending on the -concurrentfiles setting.  Additionally, the 'maxgoperfile' argument controls how many sub-routines are spawned to handle the batches for each individual file - therefore, if you had this set to 1, you would have 10k goroutines spawned at any given time - if you used 20 as is default, there would be upwards of 200,000 goroutines spawned assuming all file processing happened concurrently. 

Realistically, this should not cause any issues on most modern machines - a machine with 4 GB of RAM is capable of easily handling ~1,000,000 goroutines - but now we have to take into account the files we are processing - this is where batchsize becomes important.  We must select a batchsize that is appropriate to both the data we are treating as well as the machine we are operating on - the defaults are typically good starting points to ensure work is processed efficiently but should be played with if performance is poor.

Additionally, the -concurrentfiles flag can be used to limit the number of files processed concurrently - this defaults to 100 - together with -batchsize and -maxgoperfile the user can tweak the various concurrency settings associated with file processing to ensure performance and memory usage are suitable to the task and system at hand.

On top of this - as lines are sent to the main writer for each output file, they are buffered into a slice before writing to file to help improve throughput - the amount of lines buffered at a time for each output file can be controlled via the -writebuffer parameter - defaulting to 1000.

### DNS Notes
LogBoost is capable of generating an enormous amount of DNS queries depending on the input data - when an execution is started, an in-memory cache is established to hold DNS record responses for each detected IP address - this helps reduce redundant DNS requests for the same IP address, improving overall throughput.

Still, be aware that '-dns' can have a large impact on the overall execution time when dealing with a large amount of IP addresses - it may make sense to reduce overall batch size and increase maxgoperfile to help split DNS requests across more go routines.

Additionally - it is possible for DNS requests to be throttled by upstream servers such as Google DNS - this can be an issue when dealing with a large amount of data.

To help mitigate this, DNS results are cached for re-use - when execution is complete, the cache is saved to the directory 'dns.cache' - this cache is re-used on any additional execution from the same working directory - this means that if an IP address exists in the cache, we will not make new queries for it.  If you want to perform 'fresh' queries, just delete the cache directory and it will be rebuilt automatically.
### Handling Different Log Types

#### CSV
Handling CSV input is straight forward:
1. Point LogBoost at the logs via '-logdir'
2. Either tell LogBoost which column contains an IP address with '-ipcol' or use '-regex' to have it scan each line for the first non-private IP address
3. That's it - you can use additional settings if desired such as '-dns', '-useti' or the date filtering flags but this is enough for basic processing of standard CSVs.
```
LogBoost.exe -logdir C:\csvfiles
```
If we are processing a directory that contains time-delimited files, it may be useful to also include '-combine' to push similar files together in each output directory.
```
LogBoost.exe -logdir C:\csvfiles -combine
```
To expand an embedded JSON blob, use '-jsoncol' and provide the column name - by default, 'AuditData' is used to help with Azure Audit Exports.  Also use fullparse to enable this functionality.
```
LogBoost.exe -logdir C:\csvwithjson -jsoncol "jsondata" -fullparse
```

#### IIS/W3C/ELF/CLF (Web Server Style Logging)
1. Tell LogBoost where to find the logs via '-logdir'
2. Include the '-convert' flag so we find files besides .csv
3. At the core - that is all that is required - if you are processing directories that contain similar files, it may also be useful to include '-combine' to combine the outputs.
4. Optional flags such as -dns, -useti and the date filtering can also be used if desired.
```
LogBoost.exe -logdir C:\inetpub\logs -convert -combine
```

#### Common Event Format (CEF)
Handling is similar to above - since these are typically not CSV files, we need to use '-convert' flag to find/parse them.

LogBoost is currently capable of detecting/parsing 4 types of CEF input, with line samples provided below:
* CEF with syslog RFC 3164 Header
  * <6>Sep 14 14:12:51 10.1.1.143 CEF:0|.....
* CEF with syslog RFC 5424 Header
  * <34>1 2003-10-11T22:14:15.003Z mymachine.example.com CEF:0|.....
* CEF with a generic syslog Header
  * Jun 27 18:19:37 ip-172-31-82-74 systemd[1]: CEF:0|.....
* CEF without any prefixes/headers
  * CEF:0|.....

Additionally, LogBoost is capable of parsing out all possible K=V extensions in a given file and using these as column headers, in effect 'flattening' the CEF extensions for easier filtering.  This can be enabled via the '-fullparse' flag - this will increase processing time as we need to read the file twice - once to gather all possible headers and again to actually parse it.

#### JSON
LogBoost is capable of performing either shallow or deep parsing of per-line JSON message logging such as below:
```
{"type":"liberty_accesslog","host":"79e8ad2347b3","ibm_userDir":"\/opt\/ibm\/wlp\/usr\/","ibm_serverName":"defaultServer","ibm_remoteHost":"172.27.0.10","ibm_requestProtocol":"HTTP\/1.1","ibm_userAgent":"Apache-CXF/3.3.3-SNAPSHOT","ibm_requestHeader_headername":"header_value","ibm_requestMethod":"GET","ibm_responseHeader_connection":"Close","ibm_requestPort":"9080","ibm_requestFirstLine":"GET \/favicon.ico HTTP\/1.1","ibm_responseCode":200,"ibm_requestStartTime":"2020-07-14T13:28:19.887-0400","ibm_remoteUserID":"user","ibm_uriPath":"\/favicon.ico","ibm_elapsedTime":834,"ibm_accessLogDatetime":"2020-07-14T13:28:19.887-0400","ibm_remoteIP":"172.27.0.9","ibm_requestHost":"172.27.0.9","ibm_bytesSent":15086,"ibm_bytesReceived":15086,"ibm_cookie_cookiename":"cookie_value","ibm_requestElapsedTime":3034,"ibm_datetime":"2020-07-14T13:28:19.887-0400","ibm_sequence":"1594747699884_0000000000001"}
{"type":"liberty_accesslog","host":"79e8ad2347b3","ibm_userDir":"\/opt\/ibm\/wlp\/usr\/","ibm_serverName":"defaultServer","ibm_remoteHost":"172.27.0.10","ibm_requestProtocol":"HTTP\/1.1","ibm_userAgent":"Apache-CXF/3.3.3-SNAPSHOT","ibm_requestHeader_headername":"header_value","ibm_requestMethod":"GET","ibm_responseHeader_connection":"Close","ibm_requestPort":"9080","ibm_requestFirstLine":"GET \/favicon.ico HTTP\/1.1","ibm_responseCode":200,"ibm_requestStartTime":"2020-07-14T13:28:19.887-0400","ibm_remoteUserID":"user","ibm_uriPath":"\/favicon.ico","ibm_elapsedTime":834,"ibm_accessLogDatetime":"2020-07-14T13:28:19.887-0400","ibm_remoteIP":"172.27.0.9","ibm_requestHost":"172.27.0.9","ibm_bytesSent":15086,"ibm_bytesReceived":15086,"ibm_cookie_cookiename":"cookie_value","ibm_requestElapsedTime":3034,"ibm_datetime":"2020-07-14T13:28:19.887-0400","ibm_sequence":"1594747699884_0000000000001"}
```
A 'shallow' parse is reading one line from the file and using only the keys present in that line as columns - any extra keys will be stored in a column named 'EXTRA_KEYS' as a raw string when parsing.
```
LogBoost.exe -logdir C:\jsonlogs -convert
```
To 'deep' parse a file means to read the entire thing once to gather all possible keys then to read again to actually parse and assign values based on detected keys.  To enable this, add -fullparse as below:
```
LogBoost.exe -logdir C:\jsonlogs -convert -fullparse
```


#### KV Messages
LogBoost is (mostly) capable of handling standard KV-style log formats - the default delimiter is '=' and the default kv separator is ',' - for example, to parse a file containing lines such as:
```
timestamp="Jun 12 2023 00:00:00.000", source=host1, message="test message", ip=1.1.1.1
timestamp="Jun 12 2023 00:00:00.000", source=host1, message="test message", ip=1.1.1.1 
```
Just use the below commandline:
```
LogBoost.exe -logdir C:\kvlogs -convert
```
Since this file uses standard separator/delimiter, nothing special is required.  If instead the file looked like this:
```
timestamp:"Jun 12 2023 00:00:00.000"| source:host1| message:"test message"| ip:1.1.1.1
timestamp:"Jun 12 2023 00:00:00.000"| source:host1| message:"test message"| ip:1.1.1.1 
```
Then alter your command like below:
```
LogBoost.exe -logdir C:\kvlogs -convert -separator "|" -delimiter ":"
```

#### Generic Syslog
Nothing special required here - similar to IIS/CEF/etc, just specify your log directory and use '-convert' - but since syslog and similar files normally do not have an extension, make sure to also use '-getall' - this flag makes LogBoost try to process any type of file in the log directory, not just .csv, .txt or .log.

By defaut, LogBoost can parse generic syslog, RFC5424 and RFC3164, with examples of each provided below.
* Generic
  * Jun 27 18:19:37 ip-172-31-82-74 systemd[1]: MESSAGE
  * Jun 27 18:17:39 ip-172-31-82-74 sudo: MESSAGE
* RFC 5424
* <34>1 2003-10-11T22:14:15.003Z mymachine.example.com MESSAGE
* RFC 3164
  * <6>Sep 14 14:12:51 10.1.1.143 MESSAGE

#### Any other Text-based files
While LogBoost may not have parsers for every type of log or file-type - it can still help analysts quickly enrich any file type by using regex to find the first non-private IP address in each line of a file and enriching appropriately.

```
LogBoost.exe -logdir C:\somelogs -convert -rawtxt
```
Each line of the input file will be included in it's entirety in the first column of the resulting CSV with additional columns added for the LogBoost enrichments.

To analyze all files in a directory regardless of extension, use '-getall' - the use of '-convert' will only pick up .txt/.log files by default without this.

#### References
This section lists any pages, articles, packages or other content that was relied upon or found useful while building this utility.
* https://www.maxmind.com/en/home
* https://github.com/korylprince/ipnetgen
* https://github.com/rs/zerolog
* https://github.com/mattn/go-sqlite3
* https://github.com/VictoriaMetrics/fastcache
* https://stackoverflow.com/questions/28309988/how-to-read-from-either-gzip-or-plain-text-reader-in-golang/28332019#28332019