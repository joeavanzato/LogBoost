package main

import (
	"database/sql"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"github.com/VictoriaMetrics/fastcache"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var dnsCacheFile = "dns.cache"

// 1 GB max cache size
var dnsfastcache = fastcache.LoadFromFileOrNew(dnsCacheFile, 1_000_000_000)

func parseArgs(logger zerolog.Logger) (map[string]any, error) {
	dbDir := flag.String("dbdir", "", "Directory containing existing MaxMind DB Files (if not present in current working directory")
	logDir := flag.String("logdir", "input", "Directory containing 1 or files to process")
	outputDir := flag.String("outputdir", "output", "Directory where enriched output will be stored - defaults to '$CWD\\output'")
	column := flag.String("ipcol", "IP address", "Will check for a column with this name to find IP addresses for enrichment. (Defaults to 'IP Address' per Azure defaults)")
	jsoncolumn := flag.String("jsoncol", "AuditData", "Will check for a column with this name to find the JSON Audit blob for enrichment. (Defaults to 'AuditData' per Azure defaults)")
	regex := flag.Bool("regex", false, "If enabled, will use regex against the entire line to find the first IP address present to enrich")
	convert := flag.Bool("convert", false, "If enabled, will check for additional .log or .txt files in the logs dir, convert them to an intermediate CSV and process as normal.  Capable of parsing IIS, W3C or k:v style logs - for k:v please provide separator value via '-separator' flag and delimiter as '-delimiter' flag.")
	api := flag.String("api", "", "Provide your MaxMind API Key - if not provided, will check for environment variable 'MM_API' and then 'mm_api.txt' in cwd, in that order.")
	separator := flag.String("separator", "=", "Use provided value as separator for KV logging.  Example - if log is in format k1=v1,k2=v2 then the separator would be '='")
	delimiter := flag.String("delimiter", ",", "Use provided value as KV delimiter for KV logging. Example - if log is in format k1=v1,k2=v2 then the delimiter would be ','")
	dns := flag.Bool("dns", false, "If enabled, will do live DNS lookups on the IP address to see if it resolves to any domain records.")
	maxgoperfile := flag.Int("maxgoperfile", 20, "Maximum number of goroutines to spawn on a per-file basis for concurrent processing of data.")
	batchsize := flag.Int("batchsize", 500, "Maximum number of lines to read at a time for processing within each spawned goroutine per file.")
	concurrentfiles := flag.Int("concurrentfiles", 100, "Maximum number of files to process concurrently.")
	combine := flag.Bool("combine", false, "Combine all files in each output directory into a single CSV per-directory - this will not work if the files do not share the same header sequence/number of columns.")
	buildti := flag.Bool("buildti", false, "Build the threat intelligence database based on feed_config.json")
	updateti := flag.Bool("updateti", false, "Update (and build if it doesn't exist) the threat intelligence database based on feed_config.json")
	rawtxt := flag.Bool("rawtxt", false, "When -convert is enabled and there is no known parsing technique for the provided file, treat the entire line as a single column named raw and use regex to find the first IP to enrich.")
	useti := flag.Bool("useti", false, "Use the threat intelligence database if it exists")
	startdate := flag.String("startdate", "", "Parse and use provided value as a start date for log outputs.  If no end date is provided, will find all events from this point onwards.")
	enddate := flag.String("enddate", "", "Parse and use provided value as an end date for log outputs.  If no start date is provided, will find all events from this point prior.")
	datecol := flag.String("datecol", "", "The column containing a datetime to use - if no date can be parsed from the column, an error will be thrown and all events will be processed.")
	dateformat := flag.String("dateformat", "", "The format of the datetime column - example: \"01/02/2006\", \"2006-01-02T15:04:05Z\", etc - Golang standard formats accepted and used in time.parse()")
	getall := flag.Bool("getall", false, "Get all files in target path, regardless of extension - use with -convert to try and find a parser or alone to process everything as raw text.")
	writebuffer := flag.Int("writebuffer", 2000, "How many lines to queue at a time for writing to output CSV")
	intelfile := flag.String("intelfile", "", "The path to a local text file to be added to the threat intelligence database.  Must also specify the 'type' of intel using -inteltype.")
	inteltype := flag.String("inteltype", "", "A string-based identifier that will appear when matches occur - tor, suspicious, proxy, etc - something to identify what type of file we are ingesting.")
	summarizeti := flag.Bool("summarizeti", false, "Summarize the contents of the ThreatDB, if it exists.")
	fullparse := flag.Bool("fullparse", false, "If specified, will scan entire files for all possible keys to use in CSV rather than generalizing messages into an entire column - increases processing time.  Use to expand JSON blobs inside columnar data with -jsoncol to provide the name of the column.")
	updategeo := flag.Bool("updategeo", false, "Update local MaxMind databases, even if they are detected.")

	flag.Parse()

	if *getall {
		getAllFiles = true
	}

	arguments := map[string]any{
		"dbdir":           *dbDir,
		"logdir":          *logDir,
		"outputdir":       *outputDir,
		"IPcolumn":        *column,
		"JSONcolumn":      *jsoncolumn,
		"api":             *api,
		"regex":           *regex,
		"convert":         *convert,
		"separator":       *separator,
		"delimiter":       *delimiter,
		"dns":             *dns,
		"maxgoperfile":    *maxgoperfile,
		"batchsize":       *batchsize,
		"concurrentfiles": *concurrentfiles,
		"combine":         *combine,
		"buildti":         *buildti,
		"updateti":        *updateti,
		"useti":           *useti,
		"rawtxt":          *rawtxt,
		"startdate":       *startdate,
		"enddate":         *enddate,
		"datecol":         *datecol,
		"dateformat":      *dateformat,
		"writebuffer":     *writebuffer,
		"intelfile":       *intelfile,
		"inteltype":       *inteltype,
		"summarizeti":     *summarizeti,
		"fullparse":       *fullparse,
		"updategeo":       *updategeo,
	}

	if (*intelfile != "" && *inteltype == "") || (*intelfile == "" && *inteltype != "") {
		logger.Error().Msg("Cannot use -intelfile without -inteltype and vice-versa!")
		return make(map[string]any), errors.New("Cannot use -intelfile without -inteltype and vice-versa!\"")
	}

	if *startdate != "" {
		startimestamp, err := time.Parse("01/02/2006", *startdate)
		if err != nil {
			logger.Error().Msg("Could not parse provided startdate - ensure format is MM/DD/YYYY")
			return make(map[string]any), err
		}
		arguments["startdate"] = startimestamp
	}
	if *enddate != "" {
		endtimestamp, err := time.Parse("01/02/2006", *enddate)
		if err != nil {
			logger.Error().Msg("Could not parse provided enddate - ensure format is MM/DD/YYYY")
			return make(map[string]any), err
		}
		arguments["enddate"] = endtimestamp
	}
	if (*startdate != "" || *enddate != "") && *datecol == "" {
		logger.Error().Msg("No date column provided - cannot use startdate/enddate without providing the column to use for filtering!")
		return make(map[string]any), errors.New("No date column provided - cannot use startdate/enddate without providing the column to use for filtering!")
	}
	if *startdate == "" && *enddate == "" && *datecol != "" {
		logger.Error().Msg("No startdate or enddate provided - cannot use datecol without providing at least one date to filter!")
		return make(map[string]any), errors.New("No startdate or enddate provided - cannot use datecol without providing at least one date to filter!")
	}
	if *datecol != "" && *dateformat == "" {
		logger.Error().Msg("Must provide a date format to use when parsing via -dateformat!")
		return make(map[string]any), errors.New("Must provide a valid date format to use when parsing!")
	}

	return arguments, nil
}

func findLogsToProcess(arguments map[string]any, logger zerolog.Logger) ([]string, error) {
	logDir := arguments["logdir"].(string)
	logger.Info().Msgf("Checking for Log Files at Path: %v", logDir)
	_, err := os.Stat(logDir)
	if os.IsNotExist(err) {
		logger.Error().Msgf("Could not find directory: %v", logDir)
		return make([]string, 0), err
	}
	//globPattern := fmt.Sprintf("%v\\*.csv", logDir)
	//entries, err := filepath.Glob(globPattern)
	err = filepath.WalkDir(logDir, visit)
	if err != nil {
		logger.Error().Msg(err.Error())
		return make([]string, 0), err
	}
	logger.Info().Msgf("Found %v files to process", len(logsToProcess))
	return logsToProcess, nil
}

func visit(path string, di fs.DirEntry, err error) error {
	if di.IsDir() {
		return nil
	}
	if strings.HasSuffix(strings.ToLower(path), ".csv") || strings.HasSuffix(strings.ToLower(path), ".log") || strings.HasSuffix(strings.ToLower(path), ".txt") || getAllFiles {
		logsToProcess = append(logsToProcess, path)
	}
	return nil
}

func enrichLogs(arguments map[string]any, logFiles []string, logger zerolog.Logger) int {
	outputDir := arguments["outputdir"].(string)
	if err := os.MkdirAll(outputDir, os.ModeSticky|os.ModePerm); err != nil {
		logger.Error().Msg(err.Error())
		return 0
	}
	var waitGroup WaitGroupCount

	sizeTracker := SizeTracker{
		inputSizeMBytes:      0,
		outputSizeMBytes:     0,
		actualFilesProcessed: 0,
		mw:                   sync.RWMutex{},
	}
	jobTracker := runningJobs{
		JobCount: 0,
		mw:       sync.RWMutex{},
	}
	maxConcurrentFiles := arguments["concurrentfiles"].(int)
	tempArgs := make(map[string]any)

	if useIntel {
		db, _ := sql.Open("sqlite3", threatDBFile)
		tempArgs["db"] = db
	}
	tempArgs["dateformat"] = arguments["dateformat"].(string)
	tempArgs["datecol"] = arguments["datecol"].(string)
	_, ok := arguments["startdate"].(time.Time)
	if ok {
		tempArgs["startdate"] = arguments["startdate"].(time.Time)
	} else {
		tempArgs["startdate"] = ""
	}
	_, ok = arguments["enddate"].(time.Time)
	if ok {
		tempArgs["enddate"] = arguments["enddate"].(time.Time)
	} else {
		tempArgs["enddate"] = ""
	}
	//startDate, endDate := getDateBounds(tempArgs)

	// TODO - Check for DomainDB and add to TempArgs as a temporary measure - if this exists, we will use it instead of live DNS lookup

	for _, file := range logFiles {
		// I do not like how the below path splitting/joining is being achieved - I'm sure there is a more elegant solution...
		base := strings.ToLower(filepath.Base(file))
		if !strings.HasSuffix(base, ".csv") && !arguments["convert"].(bool) && !getAllFiles {
			// If the file is not a CSV and we have not specified 'convert' argument, skip it.
			// TODO - Should this just be default?
			continue
		}
		inputFile := file
		remainderPathSplit := strings.SplitN(filepath.Dir(file), fmt.Sprintf("%v\\", arguments["logdir"].(string)), 2)
		remainderPath := ""
		outputPath := ""
		if len(remainderPathSplit) == 2 {
			remainderPath = remainderPathSplit[1]
			outputPath = fmt.Sprintf("%v\\%v", outputDir, remainderPath)
		} else {
			outputPath = outputDir
		}
		err := os.MkdirAll(outputPath, os.ModePerm)
		if err != nil {
			logger.Error().Msg(err.Error())
			continue
		}

		baseFile := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
		baseFile += ".csv"

		outputFile := fmt.Sprintf("%v\\%v", outputPath, baseFile)

		if jobTracker.GetJobs() >= maxConcurrentFiles {
		waitForOthers:
			for {
				if jobTracker.GetJobs() >= maxConcurrentFiles {
					continue
				} else {
					jobTracker.AddJob()
					waitGroup.Add(1)
					go processFile(arguments, inputFile, outputFile, logger, &waitGroup, &sizeTracker, &jobTracker, tempArgs)
					break waitForOthers
				}
			}
		} else {
			jobTracker.AddJob()
			waitGroup.Add(1)
			go processFile(arguments, inputFile, outputFile, logger, &waitGroup, &sizeTracker, &jobTracker, tempArgs)
		}

	}
	waitGroup.Wait()
	logger.Info().Msg("Done Processing all Files!")
	logger.Info().Msgf("Input Size (Megabytes): %v", sizeTracker.inputSizeMBytes)
	logger.Info().Msgf("Output Size (Megabytes): %v", sizeTracker.outputSizeMBytes)
	return sizeTracker.actualFilesProcessed
}

func processFile(arguments map[string]any, inputFile string, outputFile string, logger zerolog.Logger, waitGroup *WaitGroupCount, sizeTracker *SizeTracker, t *runningJobs, tempArgs map[string]any) {
	// TODO - I think there is some type of concurrency bug here - not sure yet - using concurrentfiles = 10 will work when default will not.
	//logger.Info().Msgf("Processing: %v --> %v", inputFile, outputFile)
	defer t.SubJob()
	defer waitGroup.Done()

	asnDB, err := maxminddb.Open(maxMindFileLocations["ASN"])
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	defer asnDB.Close()
	cityDB, err := maxminddb.Open(maxMindFileLocations["City"])
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	defer cityDB.Close()
	countryDB, err := maxminddb.Open(maxMindFileLocations["Country"])
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	defer countryDB.Close()
	if maxMindStatus["Domain"] {
		domainDB, err := maxminddb.Open(maxMindFileLocations["Domain"])
		if err != nil {
			logger.Error().Msg(err.Error())
			return
		}
		defer domainDB.Close()
		tempArgs["domaindb"] = domainDB
	}

	fileProcessed := false
	if strings.HasSuffix(strings.ToLower(inputFile), ".csv") {
		logger.Info().Msgf("Processing CSV: %v --> %v", inputFile, outputFile)
		fileProcessed = true
		processCSV(logger, *asnDB, *cityDB, *countryDB, arguments, inputFile, outputFile, tempArgs)
	} else if arguments["convert"].(bool) || getAllFiles {
		// TODO - Parse KV style logs based on provided separator and delimiter if we are set to convert log files
		//
		// We will do checks from more specific to least specific to help prevent any mismatches on the file type

		isIISorW3c, fields, delim, err := checkIISorW3c(logger, inputFile)
		if err != nil {
			return
		}
		// IIS/W3C Format Check
		if isIISorW3c {
			logger.Info().Msgf("Processing IIS/W3C: %v --> %v", inputFile, outputFile)
			fileProcessed = true
			err := parseIISStyle(logger, *asnDB, *cityDB, *countryDB, fields, delim, arguments, inputFile, outputFile, tempArgs)
			if err != nil {
				fileProcessed = false
				logger.Error().Msg(err.Error())
			}
		}
		// JSON-based per-line logging Check
		if !fileProcessed {
			isJSON, headers, _ := checkJSON(logger, inputFile, arguments["fullparse"].(bool))
			if isJSON {
				logger.Info().Msgf("Processing JSON: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				parseErr := parseJSON(logger, *asnDB, *cityDB, *countryDB, arguments, inputFile, outputFile, tempArgs, headers)
				if parseErr != nil {
					fileProcessed = false
					logger.Error().Msg(parseErr.Error())
				}
			}
		}

		// Multi-line JSON Check - in reality we are just checking for some common headers for wellknown logs such as '{"Records": [' for AWS Cloudtrail Log Exports
		if !fileProcessed {
			isMLJSON, prefix, _ := checkMultiLineJSON(logger, inputFile, arguments["fullparse"].(bool))
			if isMLJSON {
				logger.Info().Msgf("Processing Multi-Line JSON: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				headers := parseMultiLineJSONHeaders(inputFile, prefix, arguments["fullparse"].(bool))
				someError := false
				if len(headers) == 0 {
					someError = true
					fileProcessed = false
				}
				if !someError {
					parseErr := parseMultiLineJSON(logger, *asnDB, *cityDB, *countryDB, arguments, inputFile, outputFile, tempArgs, headers, prefix)
					if parseErr != nil {
						fileProcessed = false
						logger.Error().Msg(parseErr.Error())
					}
				}

			}
		}

		// CEF Format Check
		if !fileProcessed {
			headers, cefKeys, cefFormat, _ := checkCEF(logger, inputFile, arguments["fullparse"].(bool))
			if cefFormat != -1 {
				logger.Info().Msgf("Processing CEF: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				// It is some type of valid CEF-format log file
				parseErr := parseCEF(logger, inputFile, outputFile, arguments["fullparse"].(bool), headers, cefFormat, *asnDB, *cityDB, *countryDB, arguments, tempArgs, cefKeys)
				if parseErr != nil {
					fileProcessed = false
					logger.Error().Msg(parseErr.Error())
				}
			}
		}

		// NCSA CLF Format Check
		if !fileProcessed {
			isCLF, _ := checkCLF(logger, inputFile)
			if isCLF != -1 {
				logger.Info().Msgf("Processing CLF: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				parseErr := parseCLF(logger, inputFile, outputFile, *asnDB, *cityDB, *countryDB, arguments, tempArgs, isCLF)
				if parseErr != nil {
					fileProcessed = false
					logger.Error().Msg(parseErr.Error())
				}
			}
		}

		// Generic SYSLOG Checks
		if !fileProcessed {
			isSyslog, _ := checkSyslog(logger, inputFile)
			if isSyslog != -1 {
				logger.Info().Msgf("Processing SYSLOG: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				parseErr := parseSyslog(logger, inputFile, outputFile, *asnDB, *cityDB, *countryDB, arguments, tempArgs, isSyslog)
				if parseErr != nil {
					fileProcessed = false
					logger.Error().Msg(parseErr.Error())
				}
			}
		}

		// Can we detect KV-style based on provided delimiters/separators - defaults to 'k=v,k2=v2,k3="v3"' style logging
		if !fileProcessed {
			isKV, headers, _ := checkKV(logger, inputFile, arguments)
			if isKV {
				logger.Info().Msgf("Processing KV: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				parseErr := parseKV(logger, inputFile, outputFile, *asnDB, *cityDB, *countryDB, arguments, tempArgs, headers)
				if parseErr != nil {
					fileProcessed = false
					logger.Error().Msg(parseErr.Error())
				}
			}
		}
		// Last Resort - treating as raw log, no parsing available.
		if (getAllFiles || arguments["rawtxt"].(bool)) && !fileProcessed {
			logger.Info().Msgf("Processing TXT: %v --> %v", inputFile, outputFile)
			fileProcessed = true
			err := parseRaw(logger, *asnDB, *cityDB, *countryDB, arguments, inputFile, outputFile, tempArgs)
			if err != nil {
				fileProcessed = false
				logger.Error().Msg(err.Error())
			}
		}
		// Add KV style parsing logic here or whatever other methods.
	}
	if fileProcessed {
		OfileStat, ferr := os.Stat(outputFile)
		if ferr != nil {
			return
		}
		IfileStat, ferr := os.Stat(inputFile)
		if ferr != nil {
			return
		}
		sizeTracker.AddBytes(int(IfileStat.Size()/(1<<20)), int(OfileStat.Size()/(1<<20)))
	}
}

func listenOnWriteChannel(c chan []string, w *csv.Writer, logger zerolog.Logger, outputF *os.File, bufferSize int, wait *WaitGroupCount) {
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

func processRecords(logger zerolog.Logger, records [][]string, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, ipAddressColumn int, jsonColumn int, useRegex bool, useDNS bool, channel chan []string, waitGroup *WaitGroupCount, tracker *runningJobs, tempArgs map[string]any, dateindex int) {
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
		record = enrichRecord(logger, record, asnDB, cityDB, countryDB, ipAddressColumn, jsonColumn, useRegex, useDNS, tempArgs)
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
	match := auditLogIPRegex.FindStringSubmatch(jsonBlob)
	if match != nil {
		for i, name := range match {
			results[auditLogIPRegex.SubexpNames()[i]] = name
		}
		return results["ClientIP"]
	}
	return ""
	//return net.ParseIP(results["ClientIP"])
}

func enrichRecord(logger zerolog.Logger, record []string, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, ipAddressColumn int, jsonColumn int, useRegex bool, useDNS bool, tempArgs map[string]any) []string {
	// Columns this function should append to input record (in order): ASN, Country, City, Domains, TOR, SUSPICIOUS, PROXY
	// Expects a slice representing a single log record as well as an index representing either the column where an IP address is stored or the column where a JSON blob is stored (if we are not using regex on the entire line to find an IP
	ipString := ""
	var exists bool
	if ipAddressColumn != -1 {
		//ip = net.ParseIP(record[ipAddressColumn])
		ipString = record[ipAddressColumn]
		if net.ParseIP(ipString) == nil {
			ipString, exists = regexFirstPublicIPFromString(record[ipAddressColumn])
			if !exists {
				record = append(record, "NoIP", "NoIP", "NoIP", "NoIP", "NoIP", "NoIP", "NoIP")
				return record
			}
		}
	} else if jsonColumn != -1 {
		//ip = findClientIP(logger, record[jsonColumn])
		ipString = findClientIP(logger, record[jsonColumn])
	} else if useRegex {
		//ip = findClientIP(logger, record[jsonColumn])
		ipString, exists = regexFirstPublicIPFromString(strings.Join(record, " "))
		if !exists {
			record = append(record, "NoIP", "NoIP", "NoIP", "NoIP", "NoIP", "NoIP", "NoIP")
			return record
		}
	} else {
		// Could not identify which a column storing IP address column or JSON blob and not using regex to find an IP
		record = append(record, "NA", "NA", "NA", "NA", "NA", "NA", "NA")
		return record
	}

	if ipString == "" {
		record = append(record, "NA", "NA", "NA", "NA", "NA", "NA", "NA")
		return record
	}
	ip := net.ParseIP(ipString)
	if ip == nil {
		record = append(record, "NoIP", "NoIP", "NoIP", "NoIP", "NoIP", "NoIP", "NoIP")
		return record
	}
	if isPrivateIP(ip, ipString) {
		record = append(record, ipString, "PVT", "PVT", "PVT", "PVT", "PVT", "PVT")
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
	tmpCity := City{}
	tmpAsn := ASN{}
	err := asnDB.Lookup(ip, &tmpAsn)
	if err != nil {
		//ipTmpStruct.ASNOrg = ""
		record = append(record, "")
	} else {
		//ipTmpStruct.ASNOrg = tmpAsn.AutonomousSystemOrganization
		record = append(record, tmpAsn.AutonomousSystemOrganization)
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

	if useDNS {
		// TODO - Find a better way to represent domains - maybe just encode JSON style in the column?
		// TODO - Consider adding DomainCount column
		//records, dnsExists := CheckIPDNS(ipString)

		// fastcache implementation
		value := make([]byte, 0)
		value, existsInCache := dnsfastcache.HasGet(value, []byte(ipString))
		if existsInCache {
			record = append(record, string(value))
		} else {
			dnsRecords := lookupIPRecords(ipString)
			record = append(record, strings.Join(dnsRecords, "|"))
			recordsJoined := strings.Join(dnsRecords, "|")
			dnsfastcache.Set([]byte(ipString), []byte(recordsJoined))
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
	} else {
		record = append(record, "")
	}

	if useIntel {
		// TODO - Consider setting up in-memory only cache for TI to help speed up if bottlenecks occur
		matchType, TIexists, DBError := CheckIPinTI(ipString, tempArgs["db"].(*sql.DB))
		if DBError != nil {
			//ipTmpStruct.ThreatCat = "NA"
			record = append(record, "NA")
		} else if TIexists {
			//ipTmpStruct.ThreatCat = matchType
			record = append(record, matchType)
		} else {
			//ipTmpStruct.ThreatCat = "none"
			record = append(record, "none")
		}
	} else {
		//ipTmpStruct.ThreatCat = "NA"
		record = append(record, "NA")
	}

	/*	if useDNS {
		AddIP(ipString, ipTmpStruct)
	}*/
	if maxMindStatus["Domain"] {
		tmpDomain := Domain{}
		err := tempArgs["domaindb"].(*maxminddb.Reader).Lookup(ip, &tmpDomain)
		if err != nil {
			record = append(record, "NA")
		} else {
			record = append(record, tmpDomain.Domain)
		}
	} else {
		record = append(record, "NA")
	}

	return record
}

func getCSVHeaders(csvFile string) ([]string, error) {
	inputHeaderFile, err := openInput(csvFile)
	reader := csv.NewReader(inputHeaderFile)
	defer inputHeaderFile.Close()
	headers, err := reader.Read()
	if err != nil {
		return make([]string, 0), err
	}
	return headers, nil

}

func main() {
	// TODO - Refactor all path handling to use path.Join or similar for OS-transparency

	logger := setupLogger()
	arguments, err := parseArgs(logger)
	if err != nil {
		return
	}

	err = setupPrivateNetworks()
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}

	if arguments["buildti"].(bool) || arguments["updateti"].(bool) {
		TIBuildErr := buildThreatDB(arguments, logger)
		if TIBuildErr != nil {
			logger.Error().Msg(TIBuildErr.Error())
			return
		}
		updateVPNList(logger)
		summarizeThreatDB(logger)
		return
	}
	if arguments["intelfile"].(string) != "" {
		db, err := openDBConnection(logger)
		if err != nil {
			logger.Error().Msg(err.Error())
			return
		}
		if FileExists(arguments["intelfile"].(string)) {
			err = ingestFile(arguments["intelfile"].(string), arguments["inteltype"].(string), "", db, logger)
			if err != nil {
				logger.Error().Msg(err.Error())
				return
			}
		} else {
			logger.Error().Msgf("Could not find specified file: %v", arguments["intelfile"].(string))
			return
		}
		summarizeThreatDB(logger)
		return
	}

	if arguments["summarizeti"].(bool) {
		_, err := os.Stat(threatDBFile)
		if errors.Is(err, os.ErrNotExist) {
			logger.Error().Msg(err.Error())
		} else {
			summarizeThreatDB(logger)
		}
		return
	}

	if arguments["useti"].(bool) {
		_, err := os.Stat(threatDBFile)
		if errors.Is(err, os.ErrNotExist) {
			logger.Error().Msg(err.Error())
			return
		}
		useIntel = true
	}

	//makeTorList(arguments, logger)
	APIerr := setAPIUrls(arguments, logger)
	Finderr := findOrGetDBs(arguments, logger)
	if APIerr != nil && Finderr != nil {
		return
	}

	start := time.Now()
	logFiles, err := findLogsToProcess(arguments, logger)
	if err != nil {
		return
	}
	logger.Info().Msg("Starting Log Enrichment")
	filesSuccessfullyProcessed := enrichLogs(arguments, logFiles, logger)
	t := time.Now()
	elapsed := t.Sub(start)
	logger.Info().Msgf("Actual Files Processed: %v", filesSuccessfullyProcessed)
	logger.Info().Msgf("Approximate Files per Second: %v", int(float64(filesSuccessfullyProcessed)/elapsed.Seconds()))
	logger.Info().Msgf("Elapsed Time: %v seconds", elapsed.Seconds())
	if arguments["combine"].(bool) {
		Cerr := combineOutputs(arguments, logger)
		if Cerr != nil {
			logger.Error().Msg(Cerr.Error())
		}
		return
	}
	saveCacheErr := dnsfastcache.SaveToFile(dnsCacheFile)
	if saveCacheErr != nil {
		logger.Error().Msg(saveCacheErr.Error())
	}
}
