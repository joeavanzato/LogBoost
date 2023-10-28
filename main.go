package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const logFile = "log2geo.log"

type anyMap map[string]interface{}

var geoLiteASNDBURL = ""
var geoLiteCityDBURL = ""
var geoLiteCountryDBURL = ""

var maxMindFiles = map[string]string{
	"ASN":     "GeoLite2-ASN.mmdb",
	"City":    "GeoLite2-City.mmdb",
	"Country": "GeoLite2-Country.mmdb",
}

var maxMindURLs = map[string]string{
	"ASN":     geoLiteASNDBURL,
	"City":    geoLiteCityDBURL,
	"Country": geoLiteCountryDBURL,
}

var maxMindStatus = map[string]bool{
	"ASN":     false,
	"City":    false,
	"Country": false,
}

var maxMindFileLocations = map[string]string{
	"ASN":     "",
	"City":    "",
	"Country": "",
}

var auditLogIPRegex = regexp.MustCompile(`.*ClientIP":"(?P<ClientIP>.*?)",.*`)

type IPCache struct {
	ASNOrg  string
	Country string
	City    string
	Domain  string
	Proxy   bool
}

var IPCacheMap = make(map[string]IPCache)
var IPCacheMapLock = sync.RWMutex{}

// TODO - Measure performance and compare to using sync.Map instead
func CheckIP(ip string) (IPCache, bool) {
	IPCacheMapLock.RLock()
	defer IPCacheMapLock.RUnlock()
	v, e := IPCacheMap[ip]
	return v, e
}
func AddIP(ip string, ipcache IPCache) {
	IPCacheMapLock.Lock()
	defer IPCacheMapLock.Unlock()
	IPCacheMap[ip] = ipcache
}

var DNSCacheMap = make(map[string][]string)
var DNSCacheMapLock = sync.RWMutex{}

// TODO - Measure performance and compare to using sync.Map instead
func CheckIPDNS(ip string) ([]string, bool) {
	DNSCacheMapLock.RLock()
	defer DNSCacheMapLock.RUnlock()
	v, e := DNSCacheMap[ip]
	return v, e
}
func AddIPDNS(ip string, records []string) {
	DNSCacheMapLock.Lock()
	defer DNSCacheMapLock.Unlock()
	DNSCacheMap[ip] = records
}

type WaitGroupCount struct {
	sync.WaitGroup
	count int64
}

func (wg *WaitGroupCount) Add(delta int) {
	atomic.AddInt64(&wg.count, int64(delta))
	wg.WaitGroup.Add(delta)
}

func (wg *WaitGroupCount) Done() {
	atomic.AddInt64(&wg.count, -1)
	wg.WaitGroup.Done()
}

func (wg *WaitGroupCount) GetCount() int {
	return int(atomic.LoadInt64(&wg.count))
}

// https://github.com/oschwald/geoip2-golang/blob/main/reader.go
// TODO - Review potential MaxMind fields to determine usefulness of any others - really depends on the 'type' of DB we have access to
// Refactor to provide fields properly from IP/ASN
// lat/lon are kind of meh but I guess could be useful for some applications - but really it depends on accuracy radius which could maybe be useful here.
type City struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`
	Traits struct {
		IsAnonymousProxy bool `maxminddb:"is_anonymous_proxy"`
	} `maxminddb:"traits"`
}

type ASN struct {
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
}

func setupLogger() zerolog.Logger {
	logFileName := logFile
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

func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func downloadFile(logger zerolog.Logger, url string, filepath string, key string) (err error) {
	logger.Info().Msgf("Downloading MaxMind %v DB to path: %v", key, filepath)
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	return nil
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
			if err := os.Mkdir(targetDir, 0755); err != nil {
				logger.Error().Msg(err.Error())
				return err
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

func findOrGetDBs(arguments map[string]any, logger zerolog.Logger) {
	dir, err := os.Getwd()
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	if arguments["dbdir"].(string) != "" {
		dir = arguments["dbdir"].(string)
	}

	logger.Info().Msgf("Checking Directory '%v' for MaxMind DBs", dir)
	globPattern := fmt.Sprintf("%v\\**\\GeoLite2-*.mmdb", dir)
	entries, err := filepath.Glob(globPattern)
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}

	for _, e := range entries {
		if strings.HasSuffix(e, maxMindFiles["ASN"]) {
			maxMindStatus["ASN"] = true
			maxMindFileLocations["ASN"] = e
		} else if strings.HasSuffix(e, maxMindFiles["City"]) {
			maxMindStatus["City"] = true
			maxMindFileLocations["City"] = e
		} else if strings.HasSuffix(e, maxMindFiles["Country"]) {
			maxMindStatus["Country"] = true
			maxMindFileLocations["Country"] = e
		}
	}

	for k, v := range maxMindStatus {
		if v == true {
			logger.Info().Msgf("Found %v DB file at: %v", k, maxMindFileLocations[k])
		} else {
			logger.Info().Msgf("Could not find %v DB at %v\\%v, downloading!", k, dir, maxMindFiles[k])
			gzFile := fmt.Sprintf("%v\\%v.tar.gz", dir, k)
			// Download It First
			err := downloadFile(logger, maxMindURLs[k], gzFile, k)
			if err != nil {
				logger.Error().Msg("Problem Downloading File!")
				logger.Error().Msg(err.Error())
				continue
			}
			// If successful, extract
			r, err := os.Open(gzFile)
			if err != nil {
				logger.Error().Msg(err.Error())
				continue
			}
			err = ExtractTarGz(r, logger, dir)
			if err != nil {
				logger.Error().Msg(err.Error())
				continue
			}
			// Once we extract, we need to find the actual mmdb file which will be located within a newly created directory of the naming format GeoLite2-KEY_*
			globPattern := fmt.Sprintf("%v\\GeoLite2-%v_*\\GeoLite2-%v.mmdb", dir, k, k)
			file, err := filepath.Glob(globPattern)
			if err != nil {
				logger.Error().Msg(err.Error())
				continue
			}
			maxMindFileLocations[k] = file[0]
		}
	}
}

func parseArgs(logger zerolog.Logger) map[string]any {
	dbDir := flag.String("dbdir", "", "Directory containing existing MaxMind DB Files (if not present in current working directory")
	logDir := flag.String("logdir", "", "Directory containing 1 or more Azure AD CSV Exports to enrich")
	outputDir := flag.String("outputdir", "output", "Directory where enriched output will be stored - defaults to '$CWD\\output'")
	column := flag.String("ipcol", "IP address", "Will check for a column with this name to find IP addresses for enrichment. (Defaults to 'IP Address' per Azure defaults)")
	jsoncolumn := flag.String("jsoncol", "AuditData", "Will check for a column with this name to find the JSON Audit blob for enrichment. (Defaults to 'AuditData' per Azure defaults)")
	flatten := flag.Bool("flatten", false, "[TODO - Does not function properly with events that have dynamic keys] - If enabled, will flatten JSON fields using the separator '_'")
	regex := flag.Bool("regex", false, "[TODO] - If enabled, will use regex against the entire line to find the first IP address present to enrich")
	convert := flag.Bool("convert", false, "If enabled, will check for additional .log or .txt files in the logs dir, convert them to an intermediate CSV and process as normal.  Capable of parsing IIS, W3C or k:v style logs - for k:v please provide separator value via '-separator' flag and delimiter as '-delimiter' flag.")
	api := flag.String("api", "", "Provide your MaxMind API Key - if not provided, will check for environment variable 'MM_API' and then 'mm_api.txt' in cwd, in that order.")
	separator := flag.String("separator", "=", "Use provided value as separator for KV logging.")
	delimiter := flag.String("delimiter", ",", "Use provided value as KV delimiter for KV logging.")
	dns := flag.Bool("dns", false, "[TODO] - If enabled, will do live DNS lookups on the IP address to see if it resolves to any domain records.")
	flag.Parse()

	arguments := map[string]any{
		"dbdir":      *dbDir,
		"logdir":     *logDir,
		"outputdir":  *outputDir,
		"IPcolumn":   *column,
		"JSONcolumn": *jsoncolumn,
		"flatten":    *flatten,
		"api":        *api,
		"regex":      *regex,
		"convert":    *convert,
		"separator":  *separator,
		"delimiter":  *delimiter,
		"dns":        *dns,
	}
	return arguments
}

func setAPIUrls(arguments map[string]any, logger zerolog.Logger) {
	apiKey := ""
	if arguments["api"].(string) == "" {
		logger.Info().Msg("API Key not provided at command line - checking for ENV VAR")
		// API not provided at cmdline
		val, exists := os.LookupEnv("MM_API")
		if exists {
			apiKey = val
			logger.Info().Msg("Environment Variable MM_API Found")
		} else {
			logger.Info().Msg("Environment Variable MM_API Not Found, checking for mm_api.txt")
			_, err := os.Stat("mm_api.txt")
			if os.IsNotExist(err) {
				logger.Error().Msgf("Could not find mm_api.txt - downloads not possible.")
				return
			}
			logger.Info().Msgf("Found mm_api.txt")
			apiKey = ReadFileToSlice("mm_api.txt", logger)[0]
		}
	} else {
		logger.Info().Msgf("Reading API Key from provided commandline")
		apiKey = arguments["api"].(string)
	}
	if apiKey == "" {
		logger.Error().Msg("Could not find valid API Key")
		return
	}
	geoLiteASNDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=%v&suffix=tar.gz", apiKey)
	geoLiteCityDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%v&suffix=tar.gz", apiKey)
	geoLiteCountryDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%v&suffix=tar.gz", apiKey)

	maxMindURLs["ASN"] = geoLiteASNDBURL
	maxMindURLs["City"] = geoLiteCityDBURL
	maxMindURLs["Country"] = geoLiteCountryDBURL
}

var logsToProcess = make([]string, 0)

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
	if strings.HasSuffix(strings.ToLower(path), ".csv") || strings.HasSuffix(strings.ToLower(path), ".log") || strings.HasSuffix(strings.ToLower(path), ".txt") {
		logsToProcess = append(logsToProcess, path)
	}
	return nil
}

func enrichLogs(arguments map[string]any, logFiles []string, logger zerolog.Logger) {
	outputDir := arguments["outputdir"].(string)
	if err := os.MkdirAll(outputDir, os.ModeSticky|os.ModePerm); err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	var waitGroup WaitGroupCount
	// Right now, we are getting the base file name and attaching it to the output directory and using this as the output path for each file
	// Instead, I want to find the dir structure from the input file and recreate as appropriate for each source file.
	// 1 - Get directory of input file
	// 2 - Split string by the logs dir to basically remove that - then we are left with remaining output dir
	// 3 - mkdirall as needed

	for _, file := range logFiles {
		base := strings.ToLower(filepath.Base(file))
		if !strings.HasSuffix(base, ".csv") && !arguments["convert"].(bool) {
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
		waitGroup.Add(1)
		go processFile(arguments, inputFile, outputFile, logger, &waitGroup)
	}
	waitGroup.Wait()
	logger.Info().Msg("Done Processing all Files!")
}

func setupHeaders(logger zerolog.Logger, arguments map[string]any, parser *csv.Reader, writer *csv.Writer) (int, int, int, []string, error) {
	// If flat CSV with no JSON, write the original headers plus new ones for the geo attributes
	// If JSON field with flatten option, write original headers, then embedded JSON headers then geo attributes
	// returns ints representing which column index in original data represents either the straight IP Address as well as JSON - -1 if does not exist.
	idx := 0
	ipAddressColumn := -1
	jsonColumn := -1
	headers := make([]string, 0)
	geoFields := []string{"_ASN", "_Country", "_City", "Proxy", "Domains"}
	newHeaderCount := 0
	for {
		record, err := parser.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return ipAddressColumn, jsonColumn, newHeaderCount, headers, err
		}

		if idx == 0 {
			// Add original fields to our headers
			headers = append(headers, record...)

			// TODO - Support multiple possible IP address fields and use the first one - let user enter slice as argument instead of only string.
			for i, k := range record {
				if strings.ToLower(k) == strings.ToLower(arguments["IPcolumn"].(string)) {
					ipAddressColumn = i
				}
				if strings.ToLower(k) == strings.ToLower(arguments["JSONcolumn"].(string)) {
					jsonColumn = i
				}
			}
			idx += 1
		} else {
			// if flatten, we check now for JSON blob column, parse out fields and add to our headers
			if jsonColumn != -1 && arguments["flatten"].(bool) {
				var d interface{}
				err := json.Unmarshal([]byte(record[jsonColumn]), &d)
				if err != nil {
					logger.Error().Msg("Failed to unmarshal JSON message")
					jsonColumn = -1
				} else {

					keys := decodeJsonKeys(d.(map[string]interface{}))
					headers = append(headers, keys...)
					newHeaderCount = len(keys)
				}
			}
			break
		}
	}

	// Add Geo fields to current header setup
	headers = append(headers, geoFields...)
	return ipAddressColumn, jsonColumn, newHeaderCount, headers, nil
}

func openInput(inputFile string) (*os.File, error) {
	inputF, err := os.Open(inputFile)
	return inputF, err
}

func createOutput(outputFile string) (*os.File, error) {
	outputF, err := os.Create(outputFile)
	return outputF, err
}

func setupReadWrite(inputF *os.File, outputF *os.File) (*csv.Reader, *csv.Writer, error) {
	writer := csv.NewWriter(outputF)
	parser := csv.NewReader(inputF)
	parser.LazyQuotes = true
	return parser, writer, nil
}

func getNewPW(logger zerolog.Logger, inputFile string, outputFile string) (*csv.Reader, *csv.Writer, error) {
	inputF, err := openInput(inputFile)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	outputF, err := createOutput(outputFile)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	parser, writer, err := setupReadWrite(inputF, outputF)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	return parser, writer, err
}

func processCSV(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, arguments map[string]any, inputFile string, outputFile string) {
	parser, writer, err := getNewPW(logger, inputFile, outputFile)
	if err != nil {
		return
	}

	ipAddressColumn, jsonColumn, newHeaderCount, headers, err := setupHeaders(logger, arguments, parser, writer)
	if err != nil {
		logger.Error().Msgf("Error Processing File: %v", err.Error())
		return
	}

	newParse, newWrite, err := getNewPW(logger, inputFile, outputFile)
	if err != nil {
		return
	}

	idx := 0
	for {
		record, err := newParse.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error().Msg(err.Error())
			return
		}
		if idx == 0 {
			err = newWrite.Write(headers)
			if err != nil {
				logger.Error().Msg(err.Error())
			}
			idx += 1
			continue
		}
		if jsonColumn != -1 && arguments["flatten"].(bool) {
			var d interface{}
			err := json.Unmarshal([]byte(record[jsonColumn]), &d)
			if err != nil {
				// Append empty values to match column headers from parsed JSON
				logger.Error().Msg("Failed to unmarshal")
				record = append(record, make([]string, newHeaderCount)...)
			} else {
				values := decodeJson(d.(map[string]interface{}))
				if len(values) != newHeaderCount {
					//logger.Error().Msg("Error - Parsed JSON Value count does not match new header count!")
					record = append(record, make([]string, newHeaderCount)...)
				} else {
					record = append(record, values...)
				}
			}
		}

		record = enrichRecord(logger, record, asnDB, cityDB, countryDB, ipAddressColumn, jsonColumn, arguments["regex"].(bool), arguments["dns"].(bool))
		err = newWrite.Write(record)
		if err != nil {
			logger.Error().Msg(err.Error())
		}
		idx += 1
	}
}

func processFile(arguments map[string]any, inputFile string, outputFile string, logger zerolog.Logger, waitGroup *WaitGroupCount) {
	logger.Info().Msgf("Processing: %v --> %v", inputFile, outputFile)
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
	if strings.HasSuffix(strings.ToLower(inputFile), ".csv") {
		processCSV(logger, *asnDB, *cityDB, *countryDB, arguments, inputFile, outputFile)
		return
	} else if (strings.HasSuffix(strings.ToLower(inputFile), ".txt") || strings.HasSuffix(strings.ToLower(inputFile), ".log")) && arguments["convert"].(bool) {
		// TODO - Parse KV style logs based on provided separator and delimiter if we are set to convert log files
		// TODO - Parse IIS/W3C style logs -
		// 1 - Check if file is IIS/W3C Log and Handle
		// 2 - If not (missing Fields# line - then assume it is some type of kv logging and use known separator/delimiter to parse out records
		isIISorW3c, fields, delim, err := checkIISorW3c(logger, inputFile)
		if err != nil {
			return
		}
		if isIISorW3c {
			err := parseIISStyle(logger, *asnDB, *cityDB, *countryDB, fields, delim, arguments, inputFile, outputFile)
			if err != nil {
				logger.Error().Msg(err.Error())
			}
			return
		}
	}
}

func parseIISStyle(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, headers []string, delim string, arguments map[string]any, inputFile string, outputFile string) error {
	inputF, err := openInput(inputFile)
	if err != nil {
		return err
	}
	defer inputF.Close()
	outputF, err := createOutput(outputFile)
	if err != nil {
		return err
	}
	defer outputF.Close()
	writer := csv.NewWriter(outputF)
	ipAddressColumn := -1
	for i, v := range headers {
		// user provided var
		if strings.ToLower(v) == strings.ToLower(arguments["IPcolumn"].(string)) {
			ipAddressColumn = i
			break
			// iis default
		} else if strings.ToLower(v) == strings.ToLower("ClientIpAddress") {
			ipAddressColumn = i
			break
		}
	}
	geoFields := []string{"_ASN", "_Country", "_City", "Proxy", "Domains"}
	headers = append(headers, geoFields...)
	err = writer.Write(headers)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	idx := 0
	scanner := bufio.NewScanner(inputF)
	// Limited to ~65k characters in a single line - won't work with crazy complex log types but should be fine for IIS/W3C
	for scanner.Scan() {
		if idx == 0 {
			idx += 1
			continue
		}
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		record := strings.Split(line, delim)
		if err := scanner.Err(); err == io.EOF {
			break
		}
		if err != nil {
			logger.Error().Msg(err.Error())
			return err
		}

		record = enrichRecord(logger, record, asnDB, cityDB, countryDB, ipAddressColumn, -1, arguments["regex"].(bool), arguments["dns"].(bool))
		err = writer.Write(record)
		if err != nil {
			logger.Error().Msg(err.Error())
		}
		idx += 1
	}
	return nil
}

func checkIISorW3c(logger zerolog.Logger, inputFile string) (bool, []string, string, error) {
	f, err := os.Open(inputFile)
	defer f.Close()
	fields := make([]string, 0)
	if err != nil {
		return false, fields, "", err
	}
	scanner := bufio.NewScanner(f)
	for i := 0; i < 8; i++ {
		if scanner.Scan() {
			if strings.HasPrefix(strings.ToLower(scanner.Text()), "#fields:") {
				fieldSplit := strings.Split(scanner.Text(), " ")
				iisStyle := false
				if len(fieldSplit) == 2 {
					// IIS style comma-separated  - #Fields field1,field2
					iisStyle = true
				}
				fieldData := strings.TrimSpace(strings.Split(scanner.Text(), "#Fields:")[1])
				// Now we have all fields - just split by either comma or space depending on iis or w3c styling
				headers := make([]string, 0)
				delim := ""
				if iisStyle {
					headers = append(headers, strings.Split(fieldData, ",")...)
					delim = ","
				} else {
					headers = append(headers, strings.Split(fieldData, " ")...)
					delim = " "
				}
				return true, headers, delim, nil
			}
		}
	}
	return false, fields, "", err
}

func findClientIP(logger zerolog.Logger, jsonBlob string) string {
	// Finds the most appropriate IP address column to enrich from an embedded Azure AD JSON Event (IE MessageTracking, Audit, etc)
	// Instead of parsing json, probably easier to just use a regex matching the potential patterns.
	// TODO - Add additional common regex for known JSON structures

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

func enrichRecord(logger zerolog.Logger, record []string, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, ipAddressColumn int, jsonColumn int, useRegex bool, useDNS bool) []string {
	// ASN, Country, City, Proxy
	// Expects a slice representing a single log record as well as an index representing either the column where an IP address is stored or the column where a JSON blob is stored (if we are not using regex on the entire line to find an IP
	//ip := net.ParseIP("0.0.0.0")
	ipString := ""
	if ipAddressColumn != -1 {
		//ip = net.ParseIP(record[ipAddressColumn])
		ipString = record[ipAddressColumn]
	} else if jsonColumn != -1 {
		//ip = findClientIP(logger, record[jsonColumn])
		ipString = findClientIP(logger, record[jsonColumn])
	} else if useRegex {
		//ip = findClientIP(logger, record[jsonColumn])
		// TODO
	} else {
		// Could not identify which a column storing IP address column or JSON blob
		record = append(record, "", "", "", "", "")
		return record
	}

	if ipString == "" {
		record = append(record, "", "", "", "", "")
		return record
	}

	ipStruct, IPCacheExists := CheckIP(ipString)
	if IPCacheExists {
		if ipStruct.Proxy {
			record = append(record, ipStruct.ASNOrg, ipStruct.Country, ipStruct.City, "true")
		}
		record = append(record, ipStruct.ASNOrg, ipStruct.Country, ipStruct.City, "false")
	}
	if !IPCacheExists {
		ipTmpStruct := IPCache{
			ASNOrg:  "",
			Country: "",
			City:    "",
			Domain:  "",
			Proxy:   false,
		}
		ip := net.ParseIP(ipString)
		if ip == nil {
			record = append(record, "", "", "", "", "")
			return record
		}
		tmpCity := City{}
		tmpAsn := ASN{}
		err := asnDB.Lookup(ip, &tmpAsn)
		if err != nil {
			ipTmpStruct.ASNOrg = ""
			record = append(record, "")
		} else {
			ipTmpStruct.ASNOrg = tmpAsn.AutonomousSystemOrganization
			record = append(record, tmpAsn.AutonomousSystemOrganization)
		}
		err = cityDB.Lookup(ip, &tmpCity)
		if err != nil {
			ipTmpStruct.Country = ""
			ipTmpStruct.City = ""
			ipTmpStruct.Proxy = false
			record = append(record, "", "", "")
		} else {
			anon := ""
			if tmpCity.Traits.IsAnonymousProxy {
				anon = "true"
				ipTmpStruct.Proxy = true
			} else {
				anon = "false"
				ipTmpStruct.Proxy = false
			}
			ipTmpStruct.Country = tmpCity.Country.Names["en"]
			ipTmpStruct.City = tmpCity.City.Names["en"]
			record = append(record, tmpCity.Country.Names["en"], tmpCity.City.Names["en"], anon)
		}
		AddIP(ipString, ipTmpStruct)
	}

	if useDNS {
		records, dnsExists := CheckIPDNS(ipString)
		baseDNS := ""
		if dnsExists {
			for _, v := range records {
				baseDNS += v
				baseDNS += ", "
			}
			record = append(record, baseDNS)
		} else {
			dnsRecords := lookupIPRecords(ipString)
			AddIPDNS(ipString, dnsRecords)
			for _, v := range dnsRecords {
				baseDNS += v
				baseDNS += ", "
			}
			record = append(record, baseDNS)
		}
	} else {
		record = append(record, "")
	}
	return record
}

func ReadFileToSlice(filename string, logger zerolog.Logger) []string {
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

func lookupIPRecords(ip string) []string {
	records, err := net.DefaultResolver.LookupAddr(context.Background(), ip)
	if err != nil {
		//fmt.Println(err.Error())
		return []string{"None"}
	}
	return records
}

func main() {
	start := time.Now()
	logger := setupLogger()
	arguments := parseArgs(logger)
	setAPIUrls(arguments, logger)
	findOrGetDBs(arguments, logger)
	logFiles, err := findLogsToProcess(arguments, logger)
	if err != nil {
		return
	}
	logger.Info().Msg("Starting Log Enrichment")
	enrichLogs(arguments, logFiles, logger)
	t := time.Now()
	elapsed := t.Sub(start)
	logger.Info().Msgf("Execution Time: %v seconds", elapsed.Seconds())

}
