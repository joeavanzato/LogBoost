package helpers

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/joeavanzato/logboost/lbtypes"
	tldparser "github.com/joeavanzato/logboost/tldparserr"
	"github.com/joeavanzato/logboost/vars"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

func SetupLogger() zerolog.Logger {
	logFileName := vars.LogFile
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		_, err := fmt.Fprintf(os.Stderr, "Couldn't Initialize Log File: %s", err)
		if err != nil {
			panic(nil)
		}
		panic(err)
	}
	cw := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
		FormatLevel: func(i interface{}) string {
			return strings.ToUpper(fmt.Sprintf("[%s]", i))
		},
	}
	cw.NoColor = true
	mw := io.MultiWriter(cw, logFile)
	logger := zerolog.New(mw).Level(zerolog.TraceLevel)
	logger = logger.With().Timestamp().Logger()
	return logger
}

// TODO - Need to determine best approach to dynamic flattening
// Option 1 - Read second row in file, expand JSON blob and use that as the baseline for what keys are allowed - throw-out extraneous keys - faster but possible data-loss, good if keys are universal
// Option 2 - Iterate over entire file once, find all possible JSON keys and store in order - then for iterate over the file AGAIN and for each record we process, check for matching key-names and fill nils - slower but no data-loss.
func decodeJson(m map[string]interface{}) []string {
	values := make([]string, 0, len(m))
	for _, v := range m {
		switch vv := v.(type) {
		case map[string]interface{}:
			for _, value := range decodeJson(vv) {
				values = append(values, value)
			}
		case string:
			values = append(values, vv)
		case float64:
			values = append(values, strconv.FormatFloat(vv, 'f', -1, 64))
		case []interface{}:
			// Arrays aren't currently handled - this would include columns such as 'AffectedColumns'
			values = append(values, "ErrorArrayNotHandled")
		case bool:
			values = append(values, strconv.FormatBool(vv))
		case nil:
			values = append(values, "ErrorNil")
		default:
			values = append(values, "ErrorTypeNotHandled")
		}
	}
	return values
}

func decodeJsonKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	/*	for k, _ := range m {
		keys = append(keys, k)
	}*/
	for k, v := range m {
		switch vv := v.(type) {
		// Map is the only special one we need to consider since there will be additional embedded keys within
		case map[string]interface{}:
			for _, kk := range decodeJsonKeys(vv) {
				keys = append(keys, kk)
			}
		default:
			keys = append(keys, k)
		}
	}
	return keys
}

func OpenInput(inputFile string) (*os.File, error) {
	inputF, err := os.Open(inputFile)
	return inputF, err
}

func CreateOutput(outputFile string) (*os.File, error) {
	outputF, err := os.Create(outputFile)
	return outputF, err
}

func setupReadWrite(inputF *os.File, outputF *os.File) (*csv.Reader, *csv.Writer, error) {
	writer := csv.NewWriter(outputF)
	parser := csv.NewReader(inputF)
	parser.LazyQuotes = true
	return parser, writer, nil
}

func GetNewPW(logger zerolog.Logger, inputFile string, outputFile string) (*csv.Reader, *csv.Writer, *os.File, *os.File, error) {
	inputF, err := OpenInput(inputFile)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	outputF, err := CreateOutput(outputFile)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	parser, writer, err := setupReadWrite(inputF, outputF)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	return parser, writer, inputF, outputF, err
}

func ExtractTarGz(gzipStream io.Reader, logger zerolog.Logger, dir string) error {
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	tarReader := tar.NewReader(uncompressedStream)
	for true {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error().Msg(err.Error())
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			targetDir := fmt.Sprintf("%v\\%v", dir, header.Name)
			err := os.MkdirAll(targetDir, 0755)
			if err != nil {
				if os.IsExist(err) {
				} else {
					logger.Error().Msgf("Error Extracting: %v", err.Error())
					return err
				}
			}
		case tar.TypeReg:
			targetDir := fmt.Sprintf("%v\\%v", dir, header.Name)
			outFile, err := os.Create(targetDir)
			if err != nil {
				logger.Error().Msg(err.Error())
				return err
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				logger.Error().Msg(err.Error())
				return err
			}
			outFile.Close()

		default:
			logger.Error().Msg(err.Error())
			return err
		}
	}
	return nil
}

func DoesFileExist(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func GetHeaders(tempArgs map[string]any, headers []string) []string {
	if !tempArgs["passthrough"].(bool) {
		headers = append(headers, vars.GeoFields...)
		if tempArgs["use_ti"].(bool) {
			headers = append(headers, vars.ThreatFields...)
		}
		if tempArgs["use_dns"].(bool) {
			headers = append(headers, vars.DNSFields...)
		}
		if tempArgs["use_whois"].(bool) {
			if tempArgs["use_dns"].(bool) {
				headers = append(headers, vars.WhoisDomainFields...)
			}
			headers = append(headers, vars.WhoisIPFields...)
		}
		if tempArgs["use_idb"].(bool) {
			headers = append(headers, vars.IDBFields...)
		}
	}
	return headers
}

func ListenOnWriteChannel(c chan []string, w *csv.Writer, logger zerolog.Logger, outputF *os.File, bufferSize int, wait *lbtypes.WaitGroupCount) {
	// TODO - Consider having pool of routines appending records to slice [][]string and a single reader drawing from this to avoid any bottle-necks
	// TODO - Consider sending writer in a goroutine with wait group, refilling buffer, etc.
	defer outputF.Close()
	defer wait.Done()
	wait.Add(1)
	tempRecords := make([][]string, 0)
	for {
		record, ok := <-c
		if !ok {
			break
		} else if len(tempRecords) <= bufferSize {
			tempRecords = append(tempRecords, record)
		} else {
			err := w.WriteAll(tempRecords)
			if err != nil {
				logger.Error().Msg(err.Error())
			}
			tempRecords = nil
		}
	}
	err := w.WriteAll(tempRecords)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	w.Flush()
	err = w.Error()
	if err != nil {
		logger.Error().Msg(err.Error())
	}
}

func ProcessRecords(logger zerolog.Logger, records [][]string, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, domainDB maxminddb.Reader, ipAddressColumn int, jsonColumn int, useRegex bool, useDNS bool, channel chan []string, waitGroup *lbtypes.WaitGroupCount, tracker *lbtypes.RunningJobs, tempArgs map[string]any, dateindex int) {
	defer waitGroup.Done()
	defer tracker.SubJob()

	for _, record := range records {
		if dateindex != -1 {
			// we are using date filtering and have a successfully identified index column to use
			recordTimestamp, err := time.Parse(tempArgs["dateformat"].(string), record[dateindex])
			if err != nil {
				logger.Error().Msgf("Could not parse timestamp (%v) using provided layout (%v)!", tempArgs["dateformat"].(string), record[dateindex])
			}
			if err == nil {
				if !(recordTimestamp.Before(tempArgs["enddate"].(time.Time)) && recordTimestamp.After(tempArgs["startdate"].(time.Time))) && !(recordTimestamp.Equal(tempArgs["enddate"].(time.Time))) && !(recordTimestamp.Equal(tempArgs["startdate"].(time.Time))) {
					//fmt.Printf("SKIP: Start Date: %v, End Date %v, Timestamp: %v \n", tempArgs["enddate"].(time.Time), tempArgs["startdate"].(time.Time), recordTimestamp)
					continue
				}
			}
		}
		if !tempArgs["passthrough"].(bool) {
			// If passthrough == false, we enrich, otherwise just convert to CSV
			record = enrichRecord(logger, record, asnDB, cityDB, countryDB, domainDB, ipAddressColumn, jsonColumn, useRegex, useDNS, tempArgs)
		}
		channel <- record
	}
}

func findClientIP(logger zerolog.Logger, jsonBlob string) string {
	// Finds the most appropriate IP address column to enrich from an embedded Azure AD JSON Event (IE MessageTracking, Audit, etc)
	// Instead of parsing json, probably easier to just use a regex matching the potential patterns.
	// TODO - Add additional common regex for known data structures

	//result := make(map[string]interface{})
	//err := json.Unmarshal([]byte(jsonBlob), &result)
	results := map[string]string{}
	match := vars.AuditLogIPRegex.FindStringSubmatch(jsonBlob)
	if match != nil {
		for i, name := range match {
			results[vars.AuditLogIPRegex.SubexpNames()[i]] = name
		}
		return results["ClientIP"]
	}
	return ""
	//return net.ParseIP(results["ClientIP"])
}

func enrichRecord(logger zerolog.Logger, record []string, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, domainDB maxminddb.Reader, ipAddressColumn int, jsonColumn int, useRegex bool, useDNS bool, tempArgs map[string]any) []string {
	// Columns this function should append to input record (in order): ASN, Country, City, Domains, TOR, SUSPICIOUS, PROXY
	// Expects a slice representing a single log record as well as an index representing either the column where an IP address is stored or the column where a JSON blob is stored (if we are not using regex on the entire line to find an IP
	isDataCenter := false
	ipString := ""
	var exists bool
	noIP := []string{"NoIP", "NoIP", "NoIP"}
	pvtIP := []string{"PVT", "PVT", "PVT"}
	NAIP := []string{"NA", "NA", "NA"}
	if ipAddressColumn != -1 {
		//ip = net.ParseIP(record[ipAddressColumn])
		ipString = record[ipAddressColumn]
		if net.ParseIP(ipString) == nil {
			ipString, exists = RegexFirstPublicIPFromString(record[ipAddressColumn])
			if !exists {
				record = append(record, noIP...)
				return record
			}
		}
	} else if jsonColumn != -1 {
		//ip = findClientIP(logger, record[jsonColumn])
		ipString = findClientIP(logger, record[jsonColumn])
		if ipString == "" {
			ipString, exists = RegexFirstPublicIPFromString(strings.Join(record, " "))
			if !exists {
				record = append(record, noIP...)
				return record
			}
		}
	} else if useRegex {
		//ip = findClientIP(logger, record[jsonColumn])
		ipString, exists = RegexFirstPublicIPFromString(strings.Join(record, " "))
		if !exists {
			record = append(record, noIP...)
			return record
		}
	} else {
		// Could not identify which a column storing IP address column or JSON blob and not using regex to find an IP
		record = append(record, NAIP...)
		return record
	}

	if ipString == "" {
		record = append(record, NAIP...)
		return record
	}
	ip := net.ParseIP(ipString)
	if ip == nil {
		record = append(record, noIP...)
		return record
	}
	if IsPrivateIP(ip, ipString) {
		record = append(record, ipString)
		record = append(record, pvtIP...)
		return record
	}
	/*	if useDNS {
		// Only use caching if we are using DNS - DB checks are fast enough that performance is impacted in a negative way if we use this all the time.
		ipStruct, IPCacheExists := CheckIP(ipString)
		if IPCacheExists {
			record = append(record, ipString, ipStruct.ASNOrg, ipStruct.Country, ipStruct.City, strings.Join(ipStruct.Domains, "|"), ipStruct.ThreatCat)
			return record
		}
	}*/

	record = append(record, ipString)

	/*	ipTmpStruct := IPCache{
		ASNOrg:    "",
		Country:   "",
		City:      "",
		Domains:   make([]string, 0),
		ThreatCat: "",
	}*/
	tmpCity := lbtypes.City{}
	tmpAsn := lbtypes.ASN{}
	err := asnDB.Lookup(ip, &tmpAsn)
	if err != nil {
		//ipTmpStruct.ASNOrg = ""
		record = append(record, "", "")
	} else {
		//ipTmpStruct.ASNOrg = tmpAsn.AutonomousSystemOrganization
		record = append(record, tmpAsn.AutonomousSystemOrganization, strconv.FormatUint(uint64(tmpAsn.AutonomousSystemNumber), 10))
		if slices.Contains(vars.DataCenterASNNumbers, strconv.FormatUint(uint64(tmpAsn.AutonomousSystemNumber), 10)) {
			isDataCenter = true
		}
	}
	err = cityDB.Lookup(ip, &tmpCity)
	if err != nil {
		//ipTmpStruct.Country = ""
		//ipTmpStruct.City = ""
		record = append(record, "", "")
	} else {
		//ipTmpStruct.Country = tmpCity.Country.Names["en"]
		//ipTmpStruct.City = tmpCity.City.Names["en"]
		record = append(record, tmpCity.Country.Names["en"], tmpCity.City.Names["en"])
	}

	if UseIntel {
		// TODO - Consider setting up in-memory only cache for already-checked TI to help speed up if bottlenecks occur
		// Need to study this at scale more
		// TODO - If we decide to add more columns later on, need to stick empty strings here.
		categories, feednames, feedcount, TIexists, DBError := CheckIPinTI(ipString, isDataCenter, tempArgs["db"].(*sql.DB))
		if DBError != nil {
			record = append(record, "DBError", "error", "error")
		} else if TIexists {
			record = append(record, categories, feedcount, feednames)
		} else {
			record = append(record, "none", "0", "none")
		}
	}

	domain := ""
	if useDNS {
		// TODO - Find a better way to represent domains - maybe just encode JSON style in the column?
		// TODO - Consider adding DomainCount column
		//records, dnsExists := CheckIPDNS(ipString)

		// fastcache implementation

		// TODO - Implement whois check here for found domains
		value := make([]byte, 0)

		value, existsInCache := vars.Dnsfastcache.HasGet(value, []byte(ipString))
		if existsInCache {
			record = append(record, string(value))
			dnsRecords := strings.Split(string(value), "|")
			_, m, td := tldparser.ParseDomain(dnsRecords[0])
			domain = fmt.Sprintf("%s.%s", m, td)
		} else {
			dnsRecords := LookupIPRecords(ipString)
			for i, v := range dnsRecords {
				dnsRecords[i] = strings.TrimSuffix(strings.TrimSpace(v), ".")
			}
			_, m, td := tldparser.ParseDomain(dnsRecords[0])
			domain = fmt.Sprintf("%s.%s", m, td)
			record = append(record, strings.Join(dnsRecords, "|"))
			recordsJoined := strings.Join(dnsRecords, "|")
			vars.Dnsfastcache.Set([]byte(ipString), []byte(recordsJoined))

		}
		// Below uses bigcache implementation
		/*		entry, dnscacheerr := dnscache.Get(ipString)
				if dnscacheerr == nil {
					record = append(record, string(entry))
				} else {
					dnsRecords := lookupIPRecords(ipString)
					//ipTmpStruct.Domains = dnsRecords
					record = append(record, strings.Join(dnsRecords, "|"))
					recordsJoined := strings.Join(dnsRecords, "|")
					recordsBytes := make([]byte, 0)
					res := []rune(recordsJoined)
					// Naive string truncation based on ASCII mostly to fit into cache entry limit
					if len(res) > cacheEntrySizeLimit {
						recordsBytes = []byte(recordsJoined)[:cacheEntrySizeLimit]
					} else {
						recordsBytes = []byte(recordsJoined)
					}
					setdnserr := dnscache.Set(ipString, recordsBytes)
					if setdnserr != nil {
						logger.Error().Msg(setdnserr.Error())
					}
				}*/
	}
	// For TLD
	if tempArgs["use_dns"].(bool) {
		if domain == "." || domain == "" {
			record = append(record, "none")
		} else {
			record = append(record, domain)
		}
	}

	// Removing for now as we can get TLD from live DNS if we are using that
	/*	if vars.MaxMindStatus["Domain"] {
			tmpDomain := lbtypes.Domain{Domain: ""}
			errDNS := domainDB.Lookup(ip, &tmpDomain)
			if errDNS != nil {
				record = append(record, "NA")
			} else {
				record = append(record, tmpDomain.Domain)
			}
		} else if useDNS {
			//TODO - Parse the identified domains (if any) and stick in as the TLD
			record = append(record, "NA")
		} else {
			record = append(record, "NA")
		}*/

	// Handling Domain WhoIS lookups if we are using DNS and have a parsed domain with tld for the IP in question
	if tempArgs["use_whois"].(bool) && domain != "" && domain != "." {
		record = append(record, DoDomainWhoisenrichment(domain)...)
	} else if tempArgs["use_whois"].(bool) && tempArgs["use_dns"].(bool) {
		// no whois used OR domain is invalid
		record = append(record, "NA", "NA", "NA", "NA")
	}

	// Handling IP Whois lookups
	if tempArgs["use_whois"].(bool) {
		record = append(record, DoIPWhoisEnrichment(ipString)...)
	}

	if tempArgs["use_idb"].(bool) {
		record = append(record, DoIDBEnrichment(ipString)...)
	}

	return record
}

// IntSlicetoStringSlice converts a slice of ints to a slice of the same length but of type string
func IntSlicetoStringSlice(s []int) []string {
	os := make([]string, len(s))
	for k, v := range s {
		os[k] = strconv.Itoa(v)
	}
	return os
}

// DoIDBEnrichment returns a slice representing enrichments from Shodan's InternetDB project using the provided IP Address as the enrichment target.
func DoIDBEnrichment(ipaddress string) []string {
	_value := make([]byte, 0)
	cacheValue, _existsInCache := vars.IDBfastcache.HasGet(_value, []byte(ipaddress))
	errorString := []string{"err", "err", "err", "err", "err"}
	if _existsInCache {
		if string(cacheValue) == "error" {
			return errorString
		} else {
			idbData := strings.Split(string(cacheValue), "&&")
			return idbData
		}
	}
	resp, err := IDB_Http_Client.Get(fmt.Sprintf("https://internetdb.shodan.io/%s", ipaddress))
	if err != nil {
		vars.IDBfastcache.Set([]byte(ipaddress), []byte("error"))
		return errorString
	}
	defer resp.Body.Close()
	if err != nil {
		vars.IDBfastcache.Set([]byte(ipaddress), []byte("error"))
		return errorString
	}
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	var p lbtypes.ShodanIDBResponse
	err = dec.Decode(&p)
	if err != nil {
		vars.IDBfastcache.Set([]byte(ipaddress), []byte("error"))
		return errorString
	}
	idbdata := make([]string, 0)
	idbdata = append(idbdata, strings.Join(p.Cpes, "|"), strings.Join(p.Hostnames, "|"), strings.Join(IntSlicetoStringSlice(p.Ports), "|"), strings.Join(p.Tags, "|"), strings.Join(p.Vulns, "|"))
	vars.IDBfastcache.Set([]byte(ipaddress), []byte(strings.Join(idbdata, "&&")))
	return idbdata
}

// DoDomainWhoisenrichment returns a slice representing enrichments from a Domain-based WhoIS lookup.
func DoDomainWhoisenrichment(domain string) []string {
	// "lb_DomainWhois_CreatedDate", "lb_DomainWhois_UpdatedDate", "lb_DomainWhois_Country", "lb_DomainWhois_Organization"
	//u, _ := tld.Parse(dnsRecords[i])
	//domain := fmt.Sprintf("%s.%s", u.Domain, u.TLD)
	// Check for cached data using this domain
	_value := make([]byte, 0)
	cacheValue, _existsInCache := vars.Whoisfastcache.HasGet(_value, []byte(domain))
	if _existsInCache {
		// If it exists, check if it was stored with an error and it not, parse it out and append the values
		if string(cacheValue) == "error" {
			return []string{"err", "err", "err", "err"}
		} else {
			whoisData := strings.Split(string(cacheValue), "|")
			return whoisData
		}
	} else {
		// Domain Does not exist in cache yet
		result2, whoiserr := Whois(domain)
		if whoiserr != nil {
			vars.Whoisfastcache.Set([]byte(domain), []byte("error"))
			return []string{"err", "err", "err", "err"}
		} else {
			// Set cache
			parsedresult, parseerr := whoisparser.Parse(result2)
			if parseerr == nil {
				whoIsData := make([]string, 0)
				if parsedresult.Domain != nil {
					whoIsData = append(whoIsData, parsedresult.Domain.CreatedDate, parsedresult.Domain.UpdatedDate)
				} else {
					whoIsData = append(whoIsData, "NA", "NA")
				}
				if parsedresult.Registrant != nil {
					whoIsData = append(whoIsData, parsedresult.Registrant.Country, parsedresult.Registrant.Organization)
				} else {
					whoIsData = append(whoIsData, "NA", "NA")
				}
				vars.Whoisfastcache.Set([]byte(domain), []byte(strings.Join(whoIsData, "|")))
				return whoIsData
			} else {
				vars.Whoisfastcache.Set([]byte(domain), []byte("error"))
				return []string{"err", "err", "err", "err"}
			}
		}
	}
	return []string{"NA", "NA", "NA", "NA"}
}

// DoIPWhoisEnrichment returns a slice representing enrichments from an IP-based WhoIS lookup.
func DoIPWhoisEnrichment(ipaddress string) []string {
	// This is pretty slow - probably will adopt just specific source code from the current used library to streamline this
	value := make([]byte, 0)
	cacheValue, existsInCache := vars.Whoisfastcache.HasGet(value, []byte(ipaddress))
	if existsInCache {
		if string(cacheValue) == "error" {
			return []string{"NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA"}
		} else {
			parsedResult, parseerr := ParseIPWhoisLookup(string(cacheValue))
			if parseerr == nil {
				// "lb_Whois_CIDR", "lb_Whois_NetName", "lb_Whois_NetType", "lb_Whois_Organization", "lb_Whois_Created", "lb_Whois_Updated", "lb_Whois_Organization", "lb_Whois_Country", "lb_Whois_Parent"
				return []string{parsedResult.CIDR, parsedResult.NetName, parsedResult.NetType, parsedResult.Customer, parsedResult.RegistrationDate, parsedResult.RegistrationUpdated, parsedResult.Country, parsedResult.Parent}
				//recordsJoined := strings.Join(dnsRecords, "|")
			} else {
				return []string{"NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA"}
			}
		}
	} else {
		//result2, whoiserr := whois.Whois(ipString)
		// IP Does not exist in cache yet
		result2, whoiserr := Whois(ipaddress)
		if result2 == "" {
			vars.Whoisfastcache.Set([]byte(ipaddress), []byte("error"))
		} else {
			vars.Whoisfastcache.Set([]byte(ipaddress), []byte(result2))
		}
		if whoiserr == nil {
			parsedResult, parseerr := ParseIPWhoisLookup(result2)
			if parseerr == nil {
				// "lb_Whois_CIDR", "lb_Whois_NetName", "lb_Whois_NetType", "lb_Whois_Organization", "lb_Whois_Created", "lb_Whois_Updated", "lb_Whois_Organization", "lb_Whois_Country", "lb_Whois_Parent"
				return []string{parsedResult.CIDR, parsedResult.NetName, parsedResult.NetType, parsedResult.Customer, parsedResult.RegistrationDate, parsedResult.RegistrationUpdated, parsedResult.Country, parsedResult.Parent}
				//recordsJoined := strings.Join(dnsRecords, "|")
			} else {
				return []string{"NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA"}
			}
		}
	}
	return []string{"NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA"}
}

type IPWhoisResult struct {
	NetRange            string
	CIDR                string
	NetName             string
	NetHandle           string
	Parent              string
	NetType             string
	OriginAS            string
	Customer            string
	RegistrationDate    string
	RegistrationUpdated string
	ReferenceURL        string
	CustomerName        string
	Address             string
	City                string
	StateProv           string
	PostalCode          string
	Country             string
	AddressUpdated      string
	EntityReferenceURL  string
	OrgNOCName          string
	OrgNOCEmail         string
	OrgTechName         string
	OrgTechEmail        string
	OrgAbuseName        string
	OrgAbuseEmail       string
}

func ParseIPWhoisLookup(data string) (IPWhoisResult, error) {
	var dataSplit = strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
	var result = IPWhoisResult{
		NetRange:            "",
		CIDR:                "",
		NetName:             "",
		NetHandle:           "",
		Parent:              "",
		NetType:             "",
		OriginAS:            "",
		Customer:            "",
		RegistrationDate:    "",
		RegistrationUpdated: "",
		ReferenceURL:        "",
		CustomerName:        "",
		Address:             "",
		City:                "",
		StateProv:           "",
		PostalCode:          "",
		Country:             "",
		AddressUpdated:      "",
		EntityReferenceURL:  "",
		OrgNOCName:          "",
		OrgNOCEmail:         "",
		OrgTechName:         "",
		OrgTechEmail:        "",
		OrgAbuseName:        "",
		OrgAbuseEmail:       "",
	}
	for _, v := range dataSplit {
		var value = strings.TrimSpace(v[strings.LastIndex(v, ":")+1:])
		if strings.HasPrefix(v, "NetRange") {
			result.NetRange = value
		} else if strings.HasPrefix(v, "CIDR:") {
			result.CIDR = value
		} else if strings.HasPrefix(v, "NetName:") {
			result.NetName = value
		} else if strings.HasPrefix(v, "NetHandle:") {
			result.NetHandle = value
		} else if strings.HasPrefix(v, "Parent:") {
			result.Parent = value
		} else if strings.HasPrefix(v, "NetType:") {
			result.NetType = value
		} else if strings.HasPrefix(v, "OriginAS:") {
			result.OriginAS = value
		} else if strings.HasPrefix(v, "Customer:") {
			result.Customer = value
		} else if strings.HasPrefix(v, "Organization:") {
			result.Customer = value
		} else if strings.HasPrefix(v, "Address:") {
			result.Address = value
		} else if strings.HasPrefix(v, "City:") {
			result.City = value
		} else if strings.HasPrefix(v, "StateProv:") {
			result.StateProv = value
		} else if strings.HasPrefix(v, "PostalCode:") {
			result.PostalCode = value
		} else if strings.HasPrefix(v, "Country:") {
			result.Country = value
		} else if strings.HasPrefix(v, "RegDate:") {
			result.RegistrationDate = value
		} else if strings.HasPrefix(v, "Updated:") {
			if value != "" {
				result.AddressUpdated = value
			}
		} else if strings.HasPrefix(v, "OrgNOCHandle:") {
		} else if strings.HasPrefix(v, "OrgNOCName:") {
			result.OrgNOCName = value
		} else if strings.HasPrefix(v, "OrgNOCEmail:") {
			result.OrgNOCEmail = value
		} else if strings.HasPrefix(v, "OrgTechHandle:") {

		} else if strings.HasPrefix(v, "OrgTechName:") {
			result.OrgTechName = value
		} else if strings.HasPrefix(v, "OrgTechEmail:") {
			result.OrgTechEmail = value
		} else if strings.HasPrefix(v, "OrgAbuseHandle:") {

		} else if strings.HasPrefix(v, "OrgAbuseName:") {
			result.OrgAbuseName = value
		} else if strings.HasPrefix(v, "OrgAbuseEmail:") {
			result.OrgAbuseEmail = value
		}
	}
	return result, nil
}

func CombineOutputs(arguments map[string]any, logger zerolog.Logger) error {
	logger.Info().Msg("Combining Outputs per Directory")
	logger.Info().Msg("Note: The first file in each directory will provide the headers for all subsequent files - any mismatched columns will be dropped from subsequent files.")
	fileDirMap := make(map[string][]string)

	err := filepath.WalkDir(arguments["outputdir"].(string), func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			fileDirMap[filepath.Dir(path)] = append(fileDirMap[filepath.Dir(path)], path)
		}
		return nil
	})
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}

	var MainWaiter sync.WaitGroup
	for k := range fileDirMap {
		if len(fileDirMap[k]) == 0 {
			continue
		}

		var waiter lbtypes.WaitGroupCount
		writeChannel := make(chan []string)
		t := time.Now().Format("20060102150405")
		tmpCombinedOutput := fmt.Sprintf("%v\\combinedOutput_%v.csv", k, t)
		outputF, err := CreateOutput(tmpCombinedOutput)
		if err != nil {
			logger.Error().Msg(err.Error())
			continue
		}
		headers, err := getCSVHeaders(fileDirMap[k][0])
		if err != nil {
			logger.Error().Msg(err.Error())
			continue
		}

		headers = append(headers, "SourceFile")

		writer := csv.NewWriter(outputF)

		writer.Write(headers)
		// Now we have created an output CSV and written the headers from the first file to it - for each file we will kick off a goroutine that will read and send records to the writer channel
		// Once all readers are done, the waitgroup will be done and the per-file channel will be closed
		// Once all per-file channels are closed, are independent writers will finish and signal that the main wait group is done and we can proceed with execution

		MainWaiter.Add(1)
		go combineWriterListen(outputF, writer, writeChannel, logger, &MainWaiter)
		for _, v := range fileDirMap[k] {
			waiter.Add(1)
			go readAndSendToChannel(v, writeChannel, &waiter, logger, headers)
		}
		go CloseChannelWhenDone(writeChannel, &waiter)
	}
	logger.Info().Msg("Waiting...")
	MainWaiter.Wait()
	logger.Info().Msg("Done!")
	return nil
}

func combineWriterListen(outputF *os.File, writer *csv.Writer, c chan []string, logger zerolog.Logger, MainWaiter *sync.WaitGroup) {
	// Will receive a handle to a pre-setup CSV writer and listen on a channel for incoming records to write, breaking when the channel is closed.
	defer MainWaiter.Done()
	defer outputF.Close()
	for {
		record, ok := <-c
		if !ok {
			break
		} else {
			err := writer.Write(record)
			if err != nil {
				logger.Error().Msg(err.Error())
			}
		}
	}
	writer.Flush()
	err := writer.Error()
	if err != nil {
		logger.Error().Msg(err.Error())
	}

}

func RegexFirstPublicIPFromString(input string) (string, bool) {
	// Searches a string input for a public IPv4/IPv6 - returns the IP and true if found or nil and false if not.
	// If we find more than 1 match, check for first non-private IP
	// If there is only one match, just return it
	//fmt.Println("Input: " + input)
	match := vars.Ipv4_regex.FindAllStringSubmatch(input, -1)
	ipList := make([]string, 0)
	if match != nil {
		for _, v := range match {
			ipList = append(ipList, v[1])
		}
		// Iterate through IP matches - return the first non-private one - otherwise, just return the first one in the slice
		for _, v := range ipList {
			if !IsPrivateIP(net.ParseIP(v), v) {
				return v, true
			}
		}
		return ipList[0], true
	}
	// TODO - Implement private net checks for IPv6
	match2 := vars.Ipv6_regex.FindAllStringSubmatch(input, -1)
	if match2 != nil {
		for _, v := range match2 {
			//fmt.Println("RETURNING " + v[1])
			return v[1], true
		}
	}
	/*	if match != nil {
			for i, name := range ipv4_regex.SubexpNames() {
				if i != 0 && name != "" {

					return match[i], true
				}
			}
		}
		match2 := ipv6_regex.FindStringSubmatch(input)
		if match2 != nil {
			for i, _ := range ipv4_regex.SubexpNames() {
				return match2[i], true
			}
		}*/
	//fmt.Println("RETURNING FALSE")
	return "", false
}

func FileToSlice(filename string, logger zerolog.Logger) []string {
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		logger.Error().Err(err)
		return make([]string, 0)
	}
	reader := bufio.NewReader(file)
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		lines = append(lines, strings.TrimSpace(line))
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error().Err(err)
			return make([]string, 0)
		}
	}
	return lines
	//reader := bufio.NewReader(file)
}

func FindTargetIndexInSlice(headers []string, targetCol string) int {
	// Check a slice for a target string - if it exists, return the index, otherwise, -1
	for i, v := range headers {
		v := strings.ReplaceAll(v, "\"", "")
		if v == targetCol || strings.Contains(v, targetCol) {
			return i
		}
	}
	return -1
}

func CloseChannelWhenDone(c chan []string, wg *lbtypes.WaitGroupCount) {
	// Waits on a WaitGroup to conclude and closes the associated channel when done - used to synchronize waitgroups sending to a channel
	wg.Wait()
	close(c)
}

func isDateInRange(eventTimestamp string, arguments map[string]any) (bool, error) {
	// Receive a target date and compare to startdate and enddate timestamp - return true if..
	// If startdate provided with no enddate and eventTimestamp is after startdate
	// If enddate provided with no startdate and eventTimestamp is before enddate
	// If both startdate and enddate are provided and eventTimestamp is startdate <= eventTimestamp <= enddate

	// DEPRECATED - doing this in-line at processRecords
	return false, nil
}

func readAndSendToChannel(csvFile string, c chan []string, waiter *lbtypes.WaitGroupCount, logger zerolog.Logger, initialHeaders []string) {
	defer waiter.Done()
	inputHeaderFile, err := OpenInput(csvFile)
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	defer inputHeaderFile.Close()
	idx := 0
	reader := csv.NewReader(inputHeaderFile)
	reader.FieldsPerRecord = -1
	newIndexOrder := make([]int, 0)
	for {
		record, Ferr := reader.Read()

		if Ferr == io.EOF {
			break
		}
		if Ferr != nil {
			logger.Error().Msgf("Error Reading Record in %v: %v", csvFile, Ferr.Error())
			continue
		}
		if idx == 0 {
			/*			if !reflect.DeepEqual(initialHeaders, record) {
						logger.Error().Msgf("Header Mismatch - Skipping: %v", csvFile)
						return
					}*/
			// Instead of skipping file entirely, lets iterate through the headers and compare one by one to find mismatches
			newIndexOrder = compareHeaders(initialHeaders, record)
			idx += 1
			continue
		}
		record = resortRecord(record, newIndexOrder, initialHeaders)
		// Setting last element of record to the SourceFile column so we can understand which results come from which files when combining results
		record[len(initialHeaders)-1] = csvFile
		c <- record
	}
}

func compareHeaders(primaryHeaders []string, secondaryHeaders []string) []int {
	// return a list of indexes to discard from a record, making a new slice from remainder
	// builds a new 'index to k
	newHeaderIndex := make([]int, 0)
	for _, v := range secondaryHeaders {
		// Check if the header is in the master list - if it is, get the location - else we will drop it (-1)
		newIndex := FindTargetIndexInSlice(primaryHeaders, v)
		newHeaderIndex = append(newHeaderIndex, newIndex)
	}
	return newHeaderIndex
}

func resortRecord(record []string, sortOrder []int, initialHeaders []string) []string {
	newRecord := make([]string, len(initialHeaders))
	for i, v := range record {
		if sortOrder[i] == -1 {
			// Drop the value
			continue
		}
		newRecord[sortOrder[i]] = v
	}
	return newRecord
}

func RemoveSpace(s string) string {
	rr := make([]rune, 0, len(s))
	for _, r := range s {
		if !unicode.IsSpace(r) {
			rr = append(rr, r)
		}
	}
	return string(rr)
}

func getDateBounds(tempArgs map[string]any) (time.Time, time.Time) {
	startDate, _ := time.Parse("2006-01-02", "1800-01-01")
	endDate, _ := time.Parse("2006-01-02", "2300-01-01")
	sd, sdexist := tempArgs["startdate"].(time.Time)
	ed, edexist := tempArgs["enddate"].(time.Time)
	if sdexist {
		startDate = sd
	}
	if edexist {
		endDate = ed
	}
	return startDate, endDate
}

func ScannerFromFile(reader io.Reader) (*bufio.Scanner, error) {
	var scanner *bufio.Scanner
	bReader := bufio.NewReader(reader)
	testBytes, err := bReader.Peek(2)
	if err != nil {
		return nil, err
	}
	if testBytes[0] == 31 && testBytes[1] == 139 {
		gzipReader, err := gzip.NewReader(bReader)
		if err != nil {
			return nil, err
		}
		scanner = bufio.NewScanner(gzipReader)
	} else {
		scanner = bufio.NewScanner(bReader)
	}
	return scanner, nil
}

func BufferFromFile(inputfile *os.File) (*bufio.Reader, error) {
	var reader *bufio.Reader
	reader = bufio.NewReader(inputfile)
	testBytes, err := reader.Peek(2)
	if err != nil {
		return nil, err
	}
	if testBytes[0] == 31 && testBytes[1] == 139 {
		gr, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		reader = bufio.NewReader(gr)
	}
	return reader, nil
}

func CopyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}
	return nil
}

func getCSVHeaders(csvFile string) ([]string, error) {
	inputHeaderFile, err := OpenInput(csvFile)
	reader := csv.NewReader(inputHeaderFile)
	defer inputHeaderFile.Close()
	headers, err := reader.Read()
	if err != nil {
		return make([]string, 0), err
	}
	return headers, nil
}

func deduplicateStringSlice(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	sort.Strings(list)
	return list
}
