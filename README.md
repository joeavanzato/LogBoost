# log2geo
 
log2geo is a command-line utility designed to enrich CSV files (primarily from Azure AD) with IP address ASN, Country and City information provided by MaxMind GeoLite2 DBs.

To use this tool, a free API key from MaxMind is required - once an account is registered, a personal license key can be generated at https://www.maxmind.com/en/accounts/668938/license-key.

This license key must be provided in one of 3 ways to the tool:
* via commandline argument '-api'
* via environment variable 'MM_API'
* via file in current working directory named 'mm_api.txt'

The tool will automatically download and extract the latest version of each database if they are not found in the current working directory.

Additionally, if databases are stored elsewhere on disk, a path to the directory may be provided via the 'dbdir' argument.

### Commandline Arguments:
```
* -dbdir[string] - Specify the directory containing MaxMind DBs at the dir or one level below - if they don't exist, will attempt to download.
* -api[string] - Specify a MaxMind API key - if not provided will subsequently check for ENVVAR 'MM_API' then mm_api.txt in CWD.
* -logdir[string] - specify the directory containing one or more CSV files to process
* -outputdir[string] - specify the directory to store enriched logs - defaults to $CWD\output
* -ipcol[string] - specify the name of a column in the CSV files that stores IP addresses - defaults to 'IP address' to find Azure Signin Data column
* -jsoncol[string] - specify the name of a column in the CSV files storing Azure Audit JSON blobs - defaults to 'AuditData'
* -flatten[bool] - [TODO] - flatten a nested JSON structure into a CSV
* -regex[bool] - [TODO] - scan each line for IP address matches via regex and outpute all results to CSV
* -convert[bool] - Tells log2geo to look for .log/.txt files in the specified log directory in addition to CSV then attempts to read them in one of a few ways
    - IIS - Looks for #Fields and comma-delimited values
    - W3C - Looks for #Fields and space-delimited values
    - KV - Looks for KV-style logging based on provided -delimiter and -separator values
* -separator[string] - Used when -convert is specified and a file cannot be identified as IIS/W3C/CSV
* -delimiter[string] - Used when -convert is specified and a file cannot be identified as IIS/W3C/CSV
```

## Example Usage
```
log2geo.exe -logdir logs -api XXX
log2geo.exe -logdir C:\azureadlogs -outputdir enriched_logs : Look for all CSVs in directory 'C:\azureadlogs', output logs to 'enriched_logs' and use defaults for IP/JSON columns that may contain IP addresses (Azure Log Exports)
log2geo.exe -logdir somelogs -ipcol "IPADDRESS" : Look for all CSVs in directory 'somelogs' and subsequently enrich based on column-named 'IPADDRESS'
log2geo.exe -logdir logs -convert : log2geo will also hunt for .log/.txt files that can be converted to CSV (IIS, W3C)
```