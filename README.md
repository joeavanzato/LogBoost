# log2geo
 
log2geo is a command-line utility designed to enrich CSV files (primarily from Azure AD) with IP address ASN, Country and City information provided by MaxMind GeoLite2 DBs.

The tool is also capable of enriching reverse-mapped domain names for each IP address detected in the source files.  It is also capable of parsing IIS/W3C log files.  KV style logs is in the TODO list.

To use this tool, a free API key from MaxMind is required - once an account is registered, a personal license key can be generated at https://www.maxmind.com/en/accounts/668938/license-key.

This license key must be provided in one of 3 ways to the tool:
* via commandline argument '-api'
* via environment variable 'MM_API'
* via file in current working directory named 'mm_api.txt'

The tool will automatically download and extract the latest version of each database if they are not found in the current working directory.

Additionally, if databases are stored elsewhere on disk, a path to the directory may be provided via the 'dbdir' argument.

### Commandline Arguments:
```
-dbdir[string] (default="") - Specify the directory containing MaxMind DBs at the dir or one level below - if they don't exist, will attempt to download.
-api[string] (default="") - Specify a MaxMind API key - if not provided will subsequently check for ENVVAR 'MM_API' then mm_api.txt in CWD.
-logdir[string] (default="input") - specify the directory containing one or more CSV files to process
-outputdir[string] (default="output") - specify the directory to store enriched logs - defaults to $CWD\output
-ipcol[string] (default="IP address") - specify the name of a column in the CSV files that stores IP addresses - defaults to 'IP address' to find Azure Signin Data column
-jsoncol[string] (default="AuditData") - specify the name of a column in the CSV files storing Azure Audit JSON blobs - defaults to 'AuditData'
-flatten[bool] (default=false) - [TODO] - flatten a nested JSON structure into a CSV
-regex[bool] - [TODO] - scan each line for IP address matches via regex and outpute all results to CSV
-convert[bool] (default=false) - Tells log2geo to look for .log/.txt files in the specified log directory in addition to CSV then attempts to read them in one of a few ways
  - IIS - Looks for #Fields and comma-delimited values
  - W3C - Looks for #Fields and space-delimited values
  - KV - Looks for KV-style logging based on provided -delimiter and -separator values
-separator[string] (default="=") - Used when -convert is specified and a file cannot be identified as IIS/W3C/CSV
-delimiter[string] (default=" ") - Used when -convert is specified and a file cannot be identified as IIS/W3C/CSV
-dns[bool] (default=false) - Tell log2geo to perform reverse-lookups on detected IP addresses to find currently associated domains. 
-maxgoperfile[int] (default=20) - Limit number of goroutines spawned per file for concurrent chunk processing
-batchsize[int] (default=100) - Limit how many lines per-file are sent to each spawned goroutine
```

## Example Usage
```
log2geo.exe -logdir logs -api XXX
log2geo.exe -logdir logs -dns -maxgoperfile 20 -batchsize 100 : Process each file with up to 20 goroutines handling 100 lines per routine (20,000 concurrently) and also enrich detected IP addresses with DNS lookups
log2geo.exe -logdir C:\azureadlogs -outputdir enriched_logs : Look for all CSVs in directory 'C:\azureadlogs', output logs to 'enriched_logs' and use defaults for IP/JSON columns that may contain IP addresses (Azure Log Exports)
log2geo.exe -logdir somelogs -ipcol "IPADDRESS" : Look for all CSVs in directory 'somelogs' and subsequently enrich based on column-named 'IPADDRESS'
log2geo.exe -logdir logs -convert : log2geo will also hunt for .log/.txt files that can be converted to CSV (IIS, W3C)
```

### Performance Considerations
log2geo is capable of processing a large amount of data as all file processing is handled in separate goroutines - this means if you point it at a source directory containing 10,000 files, a minimum of 10,000 goroutines will be spawned.  Additionally, the 'maxgoperfile' argument controls how many sub-routines are spawned to handle the batches for each individual file - therefore, if you had this set to 1, you would have 10k goroutines spawned at any given time - if you used 20 as is default, there would be upwards of 200,000 goroutines spawned assuming all file processing happened concurrently. Realistically, this should not cause any issues on most modern machines - a machine with 4 GB of RAM is capable of easily handling ~1,000,000 goroutines - but now we have to take into account the files we are processing - this is where batchsize becomes important.  We must select a batchsize that is appropriate to both the data we are treating as well as the machine we are operating on - the defaults are typically good starting points to ensure work is processed efficiently but should be played with if performance is poor. 