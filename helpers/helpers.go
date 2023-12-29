package helpers

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"database/sql"
	"encoding/csv"
	"fmt"
	"github.com/joeavanzato/logboost/lbtypes"
	"github.com/joeavanzato/logboost/vars"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
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
	ipString := ""
	var exists bool
	noIP := []string{"NoIP", "NoIP", "NoIP", "NoIP", "NoIP", "NoIP", "NoIP"}
	pvtIP := []string{"PVT", "PVT", "PVT", "PVT", "PVT", "PVT"}
	NAIP := []string{"NA", "NA", "NA", "NA", "NA", "NA", "NA"}
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
		value, existsInCache := vars.Dnsfastcache.HasGet(value, []byte(ipString))
		if existsInCache {
			record = append(record, string(value))
		} else {
			dnsRecords := LookupIPRecords(ipString)
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
	} else {
		record = append(record, "")
	}

	if UseIntel {
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
	if vars.MaxMindStatus["Domain"] {
		tmpDomain := lbtypes.Domain{}
		err := domainDB.Lookup(ip, &tmpDomain)
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
	// If we find more than 1 match, check for first non-private IP
	// If there is only one match, just return it
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

func removeSpace(s string) string {
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
