package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"github.com/joeavanzato/logboost/helpers"
	"github.com/joeavanzato/logboost/lbtypes"
	"github.com/joeavanzato/logboost/parsers"
	"github.com/joeavanzato/logboost/vars"
	_ "github.com/mattn/go-sqlite3"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

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
	intelname := flag.String("intelname", "", "The name/tag to be applied to the custom intelligence.  Must also specify the 'type' of intel using -inteltype as well as the path via -intelfile")
	intelfile := flag.String("intelfile", "", "The path to a local text file to be added to the threat intelligence database.  Must also specify the 'type' of intel using -inteltype as well as the name via -intelname")
	inteltype := flag.String("inteltype", "", "A string-based identifier that will appear when matches occur - tor, suspicious, proxy, etc - something to identify what type of file we are ingesting.  Must also specify the file via -intelfile and name via -intelname.")
	summarizeti := flag.Bool("summarizeti", false, "Summarize the contents of the ThreatDB, if it exists.")
	fullparse := flag.Bool("fullparse", false, "If specified, will scan entire files for all possible keys to use in CSV rather than generalizing messages into an entire column - increases processing time.  Use to expand JSON blobs inside columnar data with -jsoncol to provide the name of the column.")
	updategeo := flag.Bool("updategeo", false, "Update local MaxMind databases, even if they are detected.")
	passthrough := flag.Bool("passthrough", false, "Skip all enrichment steps - only perform log conversion to CSV")
	includedc := flag.Bool("includedc", false, "Include datacenter list for Threat Intelligence enrichment - will add approximately ~129 million IP addresses to the DB (~7 GB on disk)")
	flag.Parse()

	if *getall {
		vars.GetAllFiles = true
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
		"intelname":       *intelname,
		"summarizeti":     *summarizeti,
		"fullparse":       *fullparse,
		"updategeo":       *updategeo,
		"passthrough":     *passthrough,
		"includedc":       *includedc,
	}

	if (*intelfile != "" && (*inteltype == "" || *intelname == "")) || ((*intelfile == "" || *intelname == "") && *inteltype != "") || ((*intelfile == "" || *inteltype == "") && *intelname != "") {
		logger.Error().Msg("Must use intelfile, intelname and inteltype together")
		return make(map[string]any), errors.New("Must use intelfile, intelname and inteltype together\"")
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
	logger.Info().Msgf("Found %v files to process", len(vars.LogsToProcess))
	return vars.LogsToProcess, nil
}

func visit(path string, di fs.DirEntry, err error) error {
	if di.IsDir() {
		return nil
	}
	if strings.HasSuffix(strings.ToLower(path), ".csv") || strings.HasSuffix(strings.ToLower(path), ".log") || strings.HasSuffix(strings.ToLower(path), ".txt") || vars.GetAllFiles {
		vars.LogsToProcess = append(vars.LogsToProcess, path)
	}
	return nil
}

func enrichLogs(arguments map[string]any, logFiles []string, logger zerolog.Logger) int {
	outputDir := arguments["outputdir"].(string)
	if err := os.MkdirAll(outputDir, os.ModeSticky|os.ModePerm); err != nil {
		logger.Error().Msg(err.Error())
		return 0
	}
	var waitGroup lbtypes.WaitGroupCount

	sizeTracker := lbtypes.SizeTracker{
		InputSizeMBytes:      0,
		OutputSizeMBytes:     0,
		ActualFilesProcessed: 0,
		Mw:                   sync.RWMutex{},
	}
	jobTracker := lbtypes.RunningJobs{
		JobCount: 0,
		Mw:       sync.RWMutex{},
	}
	maxConcurrentFiles := arguments["concurrentfiles"].(int)
	tempArgs := make(map[string]any)

	if helpers.UseIntel {
		db, _ := sql.Open("sqlite3", helpers.ThreatDBFile)
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

	tempArgs["passthrough"] = arguments["passthrough"].(bool)
	//startDate, endDate := getDateBounds(tempArgs)

	// TODO - Make this OS independent

	for _, file := range logFiles {
		// I do not like how the below path splitting/joining is being achieved - I'm sure there is a more elegant solution...
		base := strings.ToLower(filepath.Base(file))
		if !strings.HasSuffix(base, ".csv") && !arguments["convert"].(bool) && !vars.GetAllFiles {
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
	logger.Info().Msgf("Input Size (Megabytes): %v", sizeTracker.InputSizeMBytes)
	logger.Info().Msgf("Output Size (Megabytes): %v", sizeTracker.OutputSizeMBytes)
	return sizeTracker.ActualFilesProcessed
}

func processFile(arguments map[string]any, inputFile string, outputFile string, logger zerolog.Logger, waitGroup *lbtypes.WaitGroupCount, sizeTracker *lbtypes.SizeTracker, t *lbtypes.RunningJobs, tempArgs map[string]any) {
	// TODO - I think there is some type of concurrency bug here - not sure yet - using concurrentfiles = 10 will work when default will not.
	//logger.Info().Msgf("Processing: %v --> %v", inputFile, outputFile)
	defer t.SubJob()
	defer waitGroup.Done()

	//var DBRefs DBRefs

	asnDB, err := maxminddb.Open(vars.MaxMindFileLocations["ASN"])
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	defer asnDB.Close()
	//DBRefs.ASN = asnDB
	cityDB, err := maxminddb.Open(vars.MaxMindFileLocations["City"])
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	defer cityDB.Close()
	//DBRefs.City = cityDB
	countryDB, err := maxminddb.Open(vars.MaxMindFileLocations["Country"])
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	defer countryDB.Close()
	var domainDB *maxminddb.Reader
	//DBRefs.Country = countryDB
	if vars.MaxMindStatus["Domain"] {
		domainDB, err = maxminddb.Open(vars.MaxMindFileLocations["Domain"])
		if err != nil {
			logger.Error().Msg(err.Error())
			return
		}
		defer domainDB.Close()
		//DBRefs.Domain = domainDB
	} else {
		domainDB = new(maxminddb.Reader)
		//DBRefs.Domain = nil
	}

	fileProcessed := false
	if strings.HasSuffix(strings.ToLower(inputFile), ".csv") {
		logger.Info().Msgf("Processing CSV: %v --> %v", inputFile, outputFile)
		fileProcessed = true
		parsers.ProcessCSV(logger, *asnDB, *cityDB, *countryDB, *domainDB, arguments, inputFile, outputFile, tempArgs)
	} else if arguments["convert"].(bool) || vars.GetAllFiles {
		// TODO - Parse KV style logs based on provided separator and delimiter if we are set to convert log files
		//
		// We will do checks from more specific to least specific to help prevent any mismatches on the file type

		isIISorW3c, fields, delim, err := parsers.CheckIISorW3c(logger, inputFile)
		if err != nil {
			return
		}
		// IIS/W3C Format Check
		if isIISorW3c {
			logger.Info().Msgf("Processing IIS/W3C: %v --> %v", inputFile, outputFile)
			fileProcessed = true
			err := parsers.ParseIISStyle(logger, *asnDB, *cityDB, *countryDB, *domainDB, fields, delim, arguments, inputFile, outputFile, tempArgs)
			if err != nil {
				fileProcessed = false
				logger.Error().Msg(err.Error())
			}
		}

		// Multi-line JSON Check - in reality we are just checking for some common headers for wellknown logs such as '{"Records": [' for AWS Cloudtrail Log Exports
		if !fileProcessed {
			isMLJSON, prefix, _ := parsers.CheckMultiLineJSON(logger, inputFile, arguments["fullparse"].(bool))
			if isMLJSON {
				logger.Info().Msgf("Processing Multi-Line JSON: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				headers := parsers.ParseMultiLineJSONHeaders(inputFile, prefix, arguments["fullparse"].(bool))
				someError := false
				if len(headers) == 0 {
					someError = true
					fileProcessed = false
				}
				if !someError {
					parseErr := parsers.ParseMultiLineJSON(logger, *asnDB, *cityDB, *countryDB, *domainDB, arguments, inputFile, outputFile, tempArgs, headers, prefix)
					if parseErr != nil {
						fileProcessed = false
						logger.Error().Msg(parseErr.Error())
					}
				}

			}
		}

		// JSON-based per-line logging Check
		if !fileProcessed {
			isJSON, headers, _ := parsers.CheckJSON(logger, inputFile, arguments["fullparse"].(bool))
			if isJSON {
				logger.Info().Msgf("Processing JSON: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				parseErr := parsers.ParseJSON(logger, *asnDB, *cityDB, *countryDB, *domainDB, arguments, inputFile, outputFile, tempArgs, headers)
				if parseErr != nil {
					fileProcessed = false
					logger.Error().Msg(parseErr.Error())
				}
			}
		}

		// CEF Format Check
		if !fileProcessed {
			headers, cefKeys, cefFormat, _ := parsers.CheckCEF(logger, inputFile, arguments["fullparse"].(bool))
			if cefFormat != -1 {
				logger.Info().Msgf("Processing CEF: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				// It is some type of valid CEF-format log file
				parseErr := parsers.ParseCEF(logger, inputFile, outputFile, arguments["fullparse"].(bool), headers, cefFormat, *asnDB, *cityDB, *countryDB, *domainDB, arguments, tempArgs, cefKeys)
				if parseErr != nil {
					fileProcessed = false
					logger.Error().Msg(parseErr.Error())
				}
			}
		}

		// NCSA CLF Format Check
		if !fileProcessed {
			isCLF, _ := parsers.CheckCLF(logger, inputFile)
			if isCLF != -1 {
				logger.Info().Msgf("Processing CLF: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				parseErr := parsers.ParseCLF(logger, inputFile, outputFile, *asnDB, *cityDB, *countryDB, *domainDB, arguments, tempArgs, isCLF)
				if parseErr != nil {
					fileProcessed = false
					logger.Error().Msg(parseErr.Error())
				}
			}
		}

		// Generic SYSLOG Checks
		if !fileProcessed {
			isSyslog, _ := parsers.CheckSyslog(logger, inputFile)
			if isSyslog != -1 {
				logger.Info().Msgf("Processing SYSLOG: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				parseErr := parsers.ParseSyslog(logger, inputFile, outputFile, *asnDB, *cityDB, *countryDB, *domainDB, arguments, tempArgs, isSyslog)
				if parseErr != nil {
					fileProcessed = false
					logger.Error().Msg(parseErr.Error())
				}
			}
		}

		// Can we detect KV-style based on provided delimiters/separators - defaults to 'k=v,k2=v2,k3="v3"' style logging
		if !fileProcessed {
			isKV, headers, _ := parsers.CheckKV(logger, inputFile, arguments)
			if isKV {
				logger.Info().Msgf("Processing KV: %v --> %v", inputFile, outputFile)
				fileProcessed = true
				parseErr := parsers.ParseKV(logger, inputFile, outputFile, *asnDB, *cityDB, *countryDB, *domainDB, arguments, tempArgs, headers)
				if parseErr != nil {
					fileProcessed = false
					logger.Error().Msg(parseErr.Error())
				}
			}
		}
		// Last Resort - treating as raw log, no parsing available.
		if (vars.GetAllFiles || arguments["rawtxt"].(bool)) && !fileProcessed {
			logger.Info().Msgf("Processing TXT: %v --> %v", inputFile, outputFile)
			fileProcessed = true
			err := parsers.ParseRaw(logger, *asnDB, *cityDB, *countryDB, *domainDB, arguments, inputFile, outputFile, tempArgs)
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

func main() {
	// TODO - Refactor all path handling to use path.Join or similar for OS-transparency

	logger := helpers.SetupLogger()
	arguments, err := parseArgs(logger)
	if err != nil {
		return
	}

	err = helpers.SetupPrivateNetworks()
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}

	if arguments["buildti"].(bool) || arguments["updateti"].(bool) {
		TIBuildErr := helpers.BuildThreatDB(arguments, logger)
		if TIBuildErr != nil {
			logger.Error().Msg(TIBuildErr.Error())
			return
		}
		helpers.UpdateVPNList(logger)
		if arguments["includedc"].(bool) {
			helpers.UpdateDCList(logger)
		}
		helpers.SummarizeThreatDB(logger)
		return
	}
	if arguments["intelfile"].(string) != "" {
		db, err := helpers.OpenDBConnection(logger)
		if err != nil {
			logger.Error().Msg(err.Error())
			return
		}
		if !helpers.DoesFileExist(arguments["intelfile"].(string)) {
			logger.Error().Msgf("Could not find specified file: %v", arguments["intelfile"].(string))
			return
		}

		logger.Info().Msgf("Ingesting Custom Intelligence - File Path: %v, Intel Name: %v, Intel Tag %v", arguments["intelfile"].(string), arguments["intelname"].(string), arguments["inteltype"].(string))
		caterr := helpers.InsertCategory(arguments["inteltype"].(string), db)
		if caterr != nil {
			logger.Error().Msg(caterr.Error())
			return
		}
		feederr, feedid := helpers.InsertFeed(arguments["intelname"].(string), "CustomFileIngestion", db)
		if feederr != nil {
			logger.Error().Msg(feederr.Error())
			return
		}
		err = helpers.IngestFile(arguments["intelfile"].(string), arguments["inteltype"].(string), feedid, db, logger)
		if err != nil {
			logger.Error().Msg(err.Error())
			return
		}
		helpers.SummarizeThreatDB(logger)
		return
	}

	if arguments["summarizeti"].(bool) {
		_, err := os.Stat(helpers.ThreatDBFile)
		if errors.Is(err, os.ErrNotExist) {
			logger.Error().Msg(err.Error())
		} else {
			helpers.SummarizeThreatDB(logger)
		}
		return
	}

	if arguments["useti"].(bool) {
		_, err := os.Stat(helpers.ThreatDBFile)
		if errors.Is(err, os.ErrNotExist) {
			logger.Error().Msg(err.Error())
			return
		}
		helpers.UseIntel = true
	}

	if arguments["passthrough"].(bool) {
		logger.Info().Msg("Passthrough Mode Enabled - Skipping all enrichments!")
	}

	//makeTorList(arguments, logger)
	APIerr := helpers.SetAPIUrls(arguments, logger)
	Finderr := helpers.FindOrGetDBs(arguments, logger)
	if APIerr != nil && Finderr != nil && !arguments["passthrough"].(bool) {
		// We could not find an API key, could not find existing DBs and did not specify that we are doing a 'passthrough' execution
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
		Cerr := helpers.CombineOutputs(arguments, logger)
		if Cerr != nil {
			logger.Error().Msg(Cerr.Error())
		}
		return
	}
	saveCacheErr := vars.Dnsfastcache.SaveToFile(vars.DnsCacheFile)
	if saveCacheErr != nil {
		logger.Error().Msg(saveCacheErr.Error())
	}
}
