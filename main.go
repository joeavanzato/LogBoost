package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
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

// TODO - Tor Node Check
// TODO - Consider focusing on specific date range

const logFile = "log2geo.log"

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
}

// Used to help keep track of jobs in a WaitGroup
type runningJobs struct {
	JobCount int
	mw       sync.RWMutex
}

func (job *runningJobs) GetJobs() int {
	job.mw.RLock()
	defer job.mw.RUnlock()
	return job.JobCount
}
func (job *runningJobs) AddJob() {
	job.mw.Lock()
	defer job.mw.Unlock()
	job.JobCount += 1
}
func (job *runningJobs) SubJob() {
	job.mw.Lock()
	defer job.mw.Unlock()
	job.JobCount -= 1
}

// Used to track overall data size processed by the script - accessed by multiple goroutines concurrently so we make it threadsafe
type SizeTracker struct {
	inputSizeMBytes      int
	outputSizeMBytes     int
	mw                   sync.RWMutex
	actualFilesProcessed int
}

func (s *SizeTracker) AddBytes(in int, out int) {
	s.mw.Lock()
	defer s.mw.Unlock()
	s.inputSizeMBytes += in
	s.outputSizeMBytes += out
	s.actualFilesProcessed += 1
}

// This set of args is now deprecated since we are pulling down tor nodes/exit nodes as part of the -buildti, -updateti, -useti sequence of arguments
var torExitNodeURL = "https://www.dan.me.uk/torlist/?exit"
var torExitNodeFile = "tor_exit_nodes.txt"
var torNodeMap = make(map[string]struct{})
var doTorEnrich = false
var torCheckMut = sync.RWMutex{}

func CheckTor(ip string) bool {
	torCheckMut.RLock()
	defer torCheckMut.RUnlock()
	_, e := torNodeMap[ip]
	return e
}

var threatDBFile = "threats.db"
var useIntel = false
var intelDir = "intel"
var feedName = "feed_config.json"

type Feeds struct {
	Feeds []Feed `json:"feeds"`
}
type Feed struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Type string `json:"type"`
}

// Used in func visit to add log paths as we crawl the input directory
var logsToProcess = make([]string, 0)

// TODO - Put lock and map in single struct for organization - then refactor CheckIP and AddIP to just take the original cachemap struct
// TODO - Refactor to have domains be a part of the IPStruct when building this out in a more logical manner
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

// TODO - Put lock and map in single struct for organization - then refactor CheckIPDNS and AddIPDNS to just take the original cachemap struct
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

// Should probably get rid of all of the below since it really isn't necessary now that we are using the jobs tracker instead of this to limit concurrency maxes
// ////
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

// ////

var geoFields = []string{"_ASN", "_Country", "_City", "Domains", "THREATCAT"}

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

var ipv6_regex = regexp.MustCompile(`.*(?P<ip>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))).*`)
var ipv4_regex = regexp.MustCompile(`.*(?P<ip>(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})).*`)
var tenDot = net.IPNet{
	IP:   net.ParseIP("10.0.0.0"),
	Mask: net.CIDRMask(8, 32),
}
var sevenTwoDot = net.IPNet{
	IP:   net.ParseIP("172.16.0.0"),
	Mask: net.CIDRMask(12, 32),
}
var oneNineTwoDot = net.IPNet{
	IP:   net.ParseIP("192.168.0.0"),
	Mask: net.CIDRMask(16, 32),
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
	logger.Info().Msgf("Downloading File %v to path: %v", url, filepath)
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
	logDir := flag.String("logdir", "input", "Directory containing 1 or more Azure AD CSV Exports to enrich")
	outputDir := flag.String("outputdir", "output", "Directory where enriched output will be stored - defaults to '$CWD\\output'")
	column := flag.String("ipcol", "IP address", "Will check for a column with this name to find IP addresses for enrichment. (Defaults to 'IP Address' per Azure defaults)")
	jsoncolumn := flag.String("jsoncol", "AuditData", "Will check for a column with this name to find the JSON Audit blob for enrichment. (Defaults to 'AuditData' per Azure defaults)")
	flatten := flag.Bool("flatten", false, "[TODO - Does not function properly with events that have dynamic keys] - If enabled, will flatten JSON fields using the separator '_'")
	regex := flag.Bool("regex", false, "[TODO] - If enabled, will use regex against the entire line to find the first IP address present to enrich")
	convert := flag.Bool("convert", false, "If enabled, will check for additional .log or .txt files in the logs dir, convert them to an intermediate CSV and process as normal.  Capable of parsing IIS, W3C or k:v style logs - for k:v please provide separator value via '-separator' flag and delimiter as '-delimiter' flag.")
	api := flag.String("api", "", "Provide your MaxMind API Key - if not provided, will check for environment variable 'MM_API' and then 'mm_api.txt' in cwd, in that order.")
	separator := flag.String("separator", "=", "[TODO] Use provided value as separator for KV logging.")
	delimiter := flag.String("delimiter", ",", "[TODO] Use provided value as KV delimiter for KV logging.")
	dns := flag.Bool("dns", false, "[TODO] - If enabled, will do live DNS lookups on the IP address to see if it resolves to any domain records.")
	maxgoperfile := flag.Int("maxgoperfile", 20, "Maximum number of goroutines to spawn on a per-file basis for concurrent processing of data.")
	batchsize := flag.Int("batchsize", 100, "Maximum number of lines to read at a time for processing within each spawned goroutine per file.")
	concurrentfiles := flag.Int("concurrentfiles", 1000, "Maximum number of files to process concurrently.")
	combine := flag.Bool("combine", false, "Combine all files in each output directory into a single CSV per-directory - this will not work if the files do not share the same header sequence/number of columns.")
	buildti := flag.Bool("buildti", false, "Build the threat intelligence database based on feed_config.json")
	updateti := flag.Bool("updateti", false, "Update (and build if it doesn't exist) the threat intelligence database based on feed_config.json")
	useti := flag.Bool("useti", false, "Use the threat intelligence database if it exists")

	flag.Parse()

	arguments := map[string]any{
		"dbdir":           *dbDir,
		"logdir":          *logDir,
		"outputdir":       *outputDir,
		"IPcolumn":        *column,
		"JSONcolumn":      *jsoncolumn,
		"flatten":         *flatten,
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
	}
	return arguments
}

func setAPIUrls(arguments map[string]any, logger zerolog.Logger) error {
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
			}
			logger.Info().Msgf("Found mm_api.txt")
			apiKey = ReadFileToSlice("mm_api.txt", logger)[0]
		}
	} else {
		logger.Info().Msgf("Reading API Key from provided commandline")
		apiKey = arguments["api"].(string)
	}
	if apiKey == "" {
		logger.Error().Msg("Could not find valid MaxMind API Key")
		return errors.New("Could not find valid MaxMind API Key")
	}
	geoLiteASNDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=%v&suffix=tar.gz", apiKey)
	geoLiteCityDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%v&suffix=tar.gz", apiKey)
	geoLiteCountryDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%v&suffix=tar.gz", apiKey)

	maxMindURLs["ASN"] = geoLiteASNDBURL
	maxMindURLs["City"] = geoLiteCityDBURL
	maxMindURLs["Country"] = geoLiteCountryDBURL
	return nil
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
	if strings.HasSuffix(strings.ToLower(path), ".csv") || strings.HasSuffix(strings.ToLower(path), ".log") || strings.HasSuffix(strings.ToLower(path), ".txt") {
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
	for _, file := range logFiles {
		// I do not like how the below path splitting/joining is being achieved - I'm sure there is a more elegant solution...
		base := strings.ToLower(filepath.Base(file))
		if !strings.HasSuffix(base, ".csv") && !arguments["convert"].(bool) {
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
	logger.Info().Msgf("Input SizeTracker (Megabytes): %v", sizeTracker.inputSizeMBytes)
	logger.Info().Msgf("Output SizeTracker (Megabytes): %v", sizeTracker.outputSizeMBytes)
	return sizeTracker.actualFilesProcessed
}

func setupHeaders(logger zerolog.Logger, arguments map[string]any, parser *csv.Reader, writer *csv.Writer) (int, int, int, []string, error) {
	// If flat CSV with no JSON, write the original headers plus new ones for the geo attributes
	// If JSON field with flatten option, write original headers, then embedded JSON headers then geo attributes
	// returns ints representing which column index in original data represents either the straight IP Address as well as JSON - -1 if does not exist.
	idx := 0
	ipAddressColumn := -1
	jsonColumn := -1
	headers := make([]string, 0)
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

func getNewPW(logger zerolog.Logger, inputFile string, outputFile string) (*csv.Reader, *csv.Writer, *os.File, *os.File, error) {
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
	return parser, writer, inputF, outputF, err
}

func processCSV(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, arguments map[string]any, inputFile string, outputFile string, tempArgs map[string]any) {
	parser, writer, inputF1, _, err := getNewPW(logger, inputFile, outputFile)
	defer inputF1.Close()
	if err != nil {
		return
	}
	ipAddressColumn, jsonColumn, newHeaderCount, headers, err := setupHeaders(logger, arguments, parser, writer)
	if err != nil {
		logger.Error().Msgf("Error Processing File: %v", err.Error())
		return
	}

	newParse, newWrite, NewInputF, NewOutputF, err := getNewPW(logger, inputFile, outputFile)
	defer NewInputF.Close()
	if err != nil {
		return
	}

	idx := 0
	var fileWG WaitGroupCount
	recordChannel := make(chan []string)
	maxRoutinesPerFile := arguments["maxgoperfile"].(int)
	lineBatchSize := arguments["batchsize"].(int)
	jobTracker := runningJobs{
		JobCount: 0,
		mw:       sync.RWMutex{},
	}
	records := make([][]string, 0)
	go listenOnWriteChannel(recordChannel, newWrite, logger, NewOutputF)
	for {
		record, Ferr := newParse.Read()

		if Ferr == io.EOF {
			break
		}
		if Ferr != nil {
			logger.Error().Msg(Ferr.Error())
			return
		}
		if idx == 0 {
			Werr := newWrite.Write(headers)
			if Werr != nil {
				logger.Error().Msg(Werr.Error())
			}
			idx += 1
			continue
		}

		if jsonColumn != -1 && arguments["flatten"].(bool) {
			var d interface{}
			Jerr := json.Unmarshal([]byte(record[jsonColumn]), &d)
			if Jerr != nil {
				// Append empty values to match column headers from parsed JSON
				logger.Error().Msg("Failed to Unmarshal JSON")
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

		records = append(records, record)
		if len(records) <= lineBatchSize {
			continue
		} else {
			if jobTracker.GetJobs() >= maxRoutinesPerFile {
			waitForOthers:
				for {
					if jobTracker.GetJobs() >= maxRoutinesPerFile {
						continue
					} else {
						fileWG.Add(1)
						jobTracker.AddJob()
						go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, jsonColumn, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs)
						break waitForOthers
					}
				}
			} else {
				fileWG.Add(1)
				jobTracker.AddJob()
				go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, jsonColumn, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs)
			}
			records = nil
		}
		idx += 1
	}
	fileWG.Add(1)
	jobTracker.AddJob()
	go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, jsonColumn, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs)
	records = nil
	closeChannelWhenDone(recordChannel, &fileWG)
}

func processFile(arguments map[string]any, inputFile string, outputFile string, logger zerolog.Logger, waitGroup *WaitGroupCount, sizeTracker *SizeTracker, t *runningJobs, tempArgs map[string]any) {
	logger.Info().Msgf("Processing: %v --> %v", inputFile, outputFile)
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
	fileProcessed := false
	if strings.HasSuffix(strings.ToLower(inputFile), ".csv") {
		fileProcessed = true
		processCSV(logger, *asnDB, *cityDB, *countryDB, arguments, inputFile, outputFile, tempArgs)
	} else if (strings.HasSuffix(strings.ToLower(inputFile), ".txt") || strings.HasSuffix(strings.ToLower(inputFile), ".log")) && arguments["convert"].(bool) {
		// TODO - Parse KV style logs based on provided separator and delimiter if we are set to convert log files
		// 1 - Check if file is IIS/W3C Log and Handle
		// 2 - If not (missing Fields# line - then assume it is some type of kv logging and use known separator/delimiter to parse out records
		isIISorW3c, fields, delim, err := checkIISorW3c(logger, inputFile)
		if err != nil {
			return
		}
		if isIISorW3c {
			fileProcessed = true
			err := parseIISStyle(logger, *asnDB, *cityDB, *countryDB, fields, delim, arguments, inputFile, outputFile, tempArgs)
			if err != nil {
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

func parseIISStyle(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, headers []string, delim string, arguments map[string]any, inputFile string, outputFile string, tempArgs map[string]any) error {
	inputF, err := openInput(inputFile)
	defer inputF.Close()
	if err != nil {
		return err
	}
	outputF, err := createOutput(outputFile)
	if err != nil {
		return err
	}
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
		} else if strings.ToLower(v) == strings.ToLower("c-ip") {
			ipAddressColumn = i
			break
		}
	}
	headers = append(headers, geoFields...)
	err = writer.Write(headers)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	idx := 0
	scanner := bufio.NewScanner(inputF)
	// Limited to ~65k characters in a single line - won't work with crazy complex log types but should be fine for IIS/W3C
	var fileWG WaitGroupCount
	recordChannel := make(chan []string)
	maxRoutinesPerFile := arguments["maxgoperfile"].(int)
	lineBatchSize := arguments["batchsize"].(int)
	jobTracker := runningJobs{
		JobCount: 0,
		mw:       sync.RWMutex{},
	}
	records := make([][]string, 0)
	go listenOnWriteChannel(recordChannel, writer, logger, outputF)
	for scanner.Scan() {
		if idx == 0 {
			idx += 1
			continue
		}
		line := scanner.Text()
		if len(line) == 0 {
			break
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		scanErr := scanner.Err()
		if scanErr == io.EOF {
			fileWG.Add(1)
			jobTracker.AddJob()
			go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, -1, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs)
			records = nil
			break
		}
		if scanErr != nil {
			logger.Error().Msg(scanErr.Error())
			return scanErr
		}
		record := strings.Split(line, delim)
		records = append(records, record)
		if len(records) <= lineBatchSize {
			continue
		} else {
			if jobTracker.GetJobs() >= maxRoutinesPerFile {
			waitForOthers:
				for {
					if jobTracker.GetJobs() >= maxRoutinesPerFile {
						continue
					} else {
						fileWG.Add(1)
						jobTracker.AddJob()
						go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, -1, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs)
						break waitForOthers
					}
				}
			} else {
				fileWG.Add(1)
				jobTracker.AddJob()
				go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, -1, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs)
			}
			records = nil
		}
		idx += 1
	}
	fileWG.Add(1)
	// Catchall in case there are still records to process
	jobTracker.AddJob()
	go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, -1, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs)
	closeChannelWhenDone(recordChannel, &fileWG)
	return nil
}

func closeChannelWhenDone(c chan []string, wg *WaitGroupCount) {
	wg.Wait()
	close(c)
}

func listenOnWriteChannel(c chan []string, w *csv.Writer, logger zerolog.Logger, outputF *os.File) {
	// TODO - Consider having pool of routines appending records to slice [][]string and a single reader drawing from this to avoid any bottle-necks
	defer outputF.Close()
	for {
		record, ok := <-c
		if !ok {
			break
		} else {
			err := w.Write(record)
			if err != nil {
				logger.Error().Msg(err.Error())
			}
		}
	}
}

func processRecords(logger zerolog.Logger, records [][]string, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, ipAddressColumn int, jsonColumn int, useRegex bool, useDNS bool, channel chan []string, waitGroup *WaitGroupCount, tracker *runningJobs, tempArgs map[string]any) {
	defer waitGroup.Done()
	defer tracker.SubJob()
	for _, record := range records {
		record = enrichRecord(logger, record, asnDB, cityDB, countryDB, ipAddressColumn, jsonColumn, useRegex, useDNS, tempArgs)
		channel <- record
	}
}

func checkIISorW3c(logger zerolog.Logger, inputFile string) (bool, []string, string, error) {
	// Determines if a file appears to be an IIS/W3C format log by checking for a line starting with #fields within the first 8 lines of the file
	// If yes, returns the headers and detected delimiter - delimiter is identified by splitting the #fields line with a " " separator - if the length of the resulting slice is 2, this means there is only one space in the line aka the delimiter is commas
	// If the slice length is not 2, most likely we are dealing with a comma delimiter
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

func isPrivateIP(ip net.IP, ipstring string) bool {
	if tenDot.Contains(ip) || sevenTwoDot.Contains(ip) || oneNineTwoDot.Contains(ip) || ipstring == "127.0.0.1" || ipstring == "::" || ipstring == "::1" || ipstring == "0.0.0.0" {
		return true
	}

	return false
}

func enrichRecord(logger zerolog.Logger, record []string, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, ipAddressColumn int, jsonColumn int, useRegex bool, useDNS bool, tempArgs map[string]any) []string {
	// Columns this function should append to input record (in order): ASN, Country, City, Domains, TOR, SUSPICIOUS, PROXY
	// Expects a slice representing a single log record as well as an index representing either the column where an IP address is stored or the column where a JSON blob is stored (if we are not using regex on the entire line to find an IP

	ipString := ""
	var exists bool
	if ipAddressColumn != -1 {
		//ip = net.ParseIP(record[ipAddressColumn])
		ipString = record[ipAddressColumn]
	} else if jsonColumn != -1 {
		//ip = findClientIP(logger, record[jsonColumn])
		ipString = findClientIP(logger, record[jsonColumn])
	} else if useRegex {
		//ip = findClientIP(logger, record[jsonColumn])
		ipString, exists = regexFirstIPFromString(strings.Join(record, " "))
		if !exists {
			record = append(record, "NoIP", "NoIP", "NoIP", "NoIP", "NoIP")
			return record
		}
	} else {
		// Could not identify which a column storing IP address column or JSON blob and not using regex to find an IP
		record = append(record, "NA", "NA", "NA", "NA", "NA")
		return record
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		record = append(record, "NoIP", "NoIP", "NoIP", "NoIP", "NoIP")
		return record
	}
	if isPrivateIP(ip, ipString) {
		record = append(record, "PVT", "PVT", "PVT", "PVT", "PVT")
		return record
	}

	ipStruct, IPCacheExists := CheckIP(ipString)
	if IPCacheExists {
		record = append(record, ipStruct.ASNOrg, ipStruct.Country, ipStruct.City)
	}
	if !IPCacheExists {
		ipTmpStruct := IPCache{
			ASNOrg:  "",
			Country: "",
			City:    "",
			Domain:  "",
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
			record = append(record, "", "")
		} else {
			ipTmpStruct.Country = tmpCity.Country.Names["en"]
			ipTmpStruct.City = tmpCity.City.Names["en"]
			record = append(record, tmpCity.Country.Names["en"], tmpCity.City.Names["en"])
		}
		AddIP(ipString, ipTmpStruct)
	}

	if useDNS {
		// TODO - Find a better way to represent domains - maybe just encode JSON style in the column?
		// TODO - Consider adding DomainCount column
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

	/*	if doTorEnrich {
			if CheckTor(ipString) {
				record = append(record, "TRUE")
			} else {
				record = append(record, "FALSE")
			}
		} else {
			record = append(record, "")
		}*/
	if useIntel {
		matchType, TIexists, DBError := CheckIPinTI(ipString, tempArgs["db"].(*sql.DB))
		if DBError != nil {
			record = append(record, "NA")
		} else if TIexists {
			if matchType == "tor" {
				record = append(record, "TOR")
			} else if matchType == "suspicious" {
				record = append(record, "SUSPICIOUS")
			} else if matchType == "proxy" {
				record = append(record, "PROXY")
			}
		} else {
			record = append(record, "NONE")
		}
	} else {
		record = append(record, "NA")
	}

	return record
}

func CheckIPinTI(ip string, db *sql.DB) (string, bool, error) {
	query := fmt.Sprintf("select category from ips where ip = \"%v\"", ip)
	/*	stmt, err := db.Prepare(query)
		if err != nil {
			return "", false
		}
		defer stmt.Close()
		r, err := stmt.Exec()
		if err != nil {
			return "", false
		}*/
	rows, err := db.Query(query)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	for rows.Next() {
		var iptype string
		err = rows.Scan(&iptype)
		if err != nil {
			return "", false, err
		}
		return iptype, true, nil
	}
	err = rows.Err()
	if err != nil {
		return "", false, err
	}

	return "", false, err
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

func combineOutputs(arguments map[string]any, logger zerolog.Logger) error {
	// TODO - Actually implement this
	logger.Info().Msg("Combining Outputs per Directory")
	files, err := os.ReadDir(arguments["outputdir"].(string))
	if err != nil {
		return err
	}
	for _, file := range files {
		fmt.Println(file.Name())
	}
	return nil

}

func makeTorList(arguments map[string]any, logger zerolog.Logger) {
	// Deprecated now that we are pulling more holistically
	_, err := os.Stat(torExitNodeFile)
	if errors.Is(err, os.ErrNotExist) {
		err2 := downloadFile(logger, torExitNodeURL, torExitNodeFile, "")
		if err2 != nil {
			logger.Error().Msg("Error Downloading TOR Exit Nodes")
			logger.Error().Msg(err.Error())
			return
		}
	}
	// File exists - either it already existed or we downloaded it.
	torNodes := ReadFileToSlice(torExitNodeFile, logger)
	for _, v := range torNodes {
		line := strings.TrimSpace(v)
		if strings.HasPrefix(line, "#") {
			continue
		}
		torNodeMap[line] = struct{}{}
	}
	doTorEnrich = true
}

func buildThreatDB(arguments map[string]any, logger zerolog.Logger) error {
	// First check if the db exists - if not, initialize the database
	// Table name: ips
	// Columns (all string): ip, url, type
	// type values: proxy, suspicious, tor
	_, err := os.Stat(threatDBFile)
	if errors.Is(err, os.ErrNotExist) {
		initErrr := initializeThreatDB(logger)
		if initErrr != nil {
			return initErrr
		}
	}
	// If we are updating intel, lets do so now.
	// Read our feed file first to use both in intel downloads then in pushing to the sqlite
	var feeds Feeds
	jsonData, ReadErr := os.ReadFile(feedName)
	if ReadErr != nil {
		logger.Error().Msg(ReadErr.Error())
		return ReadErr
	}

	jsonErr := json.Unmarshal(jsonData, &feeds)
	if jsonErr != nil {
		logger.Error().Msg(jsonErr.Error())
		return jsonErr
	}

	if arguments["updateti"].(bool) {
		UpdateErr := updateIntelligence(logger, feeds)
		if UpdateErr != nil {
			return UpdateErr
		}
	}

	// Now we have downloaded intel to intelDir - lets go through each file and parse for ipAddress hits within each file - we will use the filename to tell us what 'type' the data should be categorized as
	ingestErr := ingestIntel(logger, feeds)
	if ingestErr != nil {
		return ingestErr
	}

	useIntel = true
	return nil
}

func updateIntelligence(logger zerolog.Logger, feeds Feeds) error {
	// Iterate through feeds and downloads each file as $FEEDNAME_TIMESTAMP.txt into newly created 'intel' directory if it does not exist
	if err := os.Mkdir(intelDir, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		logger.Error().Msg(err.Error())
		return err
	}
	//t := time.Now().Format("20060102150405")
	for i := 0; i < len(feeds.Feeds); i++ {
		destFile := fmt.Sprintf("%v\\%v.txt", intelDir, feeds.Feeds[i].Name)
		Derr := downloadFile(logger, feeds.Feeds[i].URL, destFile, "")
		if Derr != nil {
			continue
		}
	}
	return nil
}

func initializeThreatDB(logger zerolog.Logger) error {
	file, CreateErr := os.Create(threatDBFile) // Create SQLite file
	if CreateErr != nil {
		logger.Error().Msg(CreateErr.Error())
		return CreateErr
	}
	file.Close()
	db, _ := sql.Open("sqlite3", threatDBFile)
	defer db.Close()
	createTableStatement := `CREATE TABLE ips ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "ip" TEXT, "category" TEXT, "url" TEXT, UNIQUE(ip));`
	_, exeE := db.Exec(createTableStatement)
	if exeE != nil {
		logger.Error().Msg(CreateErr.Error())
		return exeE
	}
	return nil
}

func ingestIntel(logger zerolog.Logger, feeds Feeds) error {
	typeMap := make(map[string]string)
	urlMap := make(map[string]string)
	db, _ := sql.Open("sqlite3", threatDBFile)
	for i := 0; i < len(feeds.Feeds); i++ {
		typeMap[feeds.Feeds[i].Name] = feeds.Feeds[i].Type
		urlMap[feeds.Feeds[i].Name] = feeds.Feeds[i].URL
	}
	intelFiles, err := os.ReadDir(intelDir)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	for _, e := range intelFiles {
		baseNameWithoutExtension := strings.TrimSuffix(filepath.Base(e.Name()), filepath.Ext(e.Name()))
		err = ingestFile(fmt.Sprintf("%v\\%v", intelDir, e.Name()), typeMap[baseNameWithoutExtension], urlMap[baseNameWithoutExtension], db, logger)
		if err != nil {
			logger.Error().Msg(err.Error())
		}
	}

	return nil
}

func ingestFile(inputFile string, iptype string, url string, db *sql.DB, logger zerolog.Logger) error {
	fileLines := ReadFileToSlice(inputFile, logger)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("insert or ignore into ips(ip, category, url) values(?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, line := range fileLines {
		lineTrimmed := strings.TrimSpace(line)
		if strings.HasPrefix(lineTrimmed, "#") {
			continue
		}
		v, e := regexFirstIPFromString(lineTrimmed)
		if e {
			_, err = stmt.Exec(v, iptype, url)
			if err != nil {
				return err
			}
		}
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func regexFirstIPFromString(input string) (string, bool) {
	match := ipv4_regex.FindStringSubmatch(input)
	if match != nil {
		for _, ip := range match {
			return ip, true
		}
	}
	match2 := ipv6_regex.FindStringSubmatch(input)
	if match2 != nil {
		for _, ip := range match2 {
			return ip, true
		}
	}
	return "", false
}

func main() {
	// TODO - Refactor all path handling to use path.Join or similar for OS-transparency
	start := time.Now()
	logger := setupLogger()
	arguments := parseArgs(logger)
	if arguments["buildti"].(bool) || arguments["updateti"].(bool) {
		TIBuildErr := buildThreatDB(arguments, logger)
		if TIBuildErr != nil {
			return
		}
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
	if APIerr != nil {
		return
	}
	findOrGetDBs(arguments, logger)
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
}
