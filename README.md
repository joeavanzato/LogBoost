# log2geo
 
log2geo is a command-line utility designed to enrich CSV files (primarily from Azure AD) with IP address ASN, Country and City information provided by MaxMind GeoLite2 DBs.

To use this tool, a free API key from MaxMind is required - once an account is registered, a personal license key can be generated at https://www.maxmind.com/en/accounts/668938/license-key.

This license key must be provided in one of 3 ways to the tool:
* via commandline argument '-api'
* via environment variable 'MM_API'
* via file in current working directory named 'mm_api.txt'

The tool will automatically download and extract the latest version of each database if they are not found in the current working directory.

Additionally, if databases are stored elsewhere on disk, a path to the directory may be provided via the 'dbdir' argument.

Commandline Arguments:
```
* -dbdir - Specify the directory containing MaxMind DBs at the dir or one level below - if they don't exist, will attempt to download.
* -api - Specify a MaxMind API key - if not provided will subsequently check for ENVVAR 'MM_API' then mm_api.txt in CWD.
* -logdir - specify the directory containing one or more CSV files to process
* -outputdir - specify the directory to store enriched logs - defaults to $CWD\output
* -ipcol - specify the name of a column in the CSV files that stores IP addresses - defaults to 'IP address' to find Azure Signin Data column
* -jsoncol - specify the name of a column in the CSV files storing Azure Audit JSON blobs - defaults to 'AuditData'
* -flatten - [TODO] - flatten a nested JSON structure into a CSV
* -regex - [TODO] - scan each line for IP address matches via regex and outpute all results to CSV
```

## Example Usage
```
log2geo.exe -logdir logs -api XXX
log2geo.exe -logdir C:\azureadlogs -outputdir enriched_logs
log2geo.exe -logdir somelogs -ipcol "IPADDRESS"
```