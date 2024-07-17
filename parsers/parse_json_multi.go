package parsers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/joeavanzato/logboost/helpers"
	"github.com/joeavanzato/logboost/lbtypes"
	"github.com/joeavanzato/logboost/vars"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

// For parsing multi-line JSON logs such as AWS CloudTrail - very 'fixed' in nature
// This parsing module is very rigid - it currently only supports any file which begins with one of the strings listed below - anything else will be skipped.
// If we match this string, it is assumed that there is a list of JSON objects embedded within 'Records' - anything else will cause an error.

var commonJSONMultiLineHeaders = []string{"{\"Records\":[", "{\"Records\": ["}

func CheckMultiLineJSON(logger zerolog.Logger, file string, fullParse bool) (bool, string, error) {
	// This will be a naive check that basically examines the first line of the document to identify if it appears to be the start of a multi-line JSON object
	// These lbtypes of documents will often start with the string '{"Records":['
	// The general strategy will be to read the file looking for individual events as delimited by {} - so basically we will run a buffer until we find the final closing } for an event
	// Then we will process the event as normal JSON - with shallow or deep parsing like per-line JSON logging
	f, err := os.Open(file)
	defer f.Close()
	if err != nil {
		logger.Error().Msg(err.Error())
		return false, "", err
	}
	limit := make([]string, 0)
	limitMax := 20
	size := 0
	//r := bufio.NewReader(f)
	r, rerr := helpers.BufferFromFile(f)
	if rerr != nil {
		logger.Error().Msg(err.Error())
		return false, "", rerr
	}

	for {
		if c, sz, err := r.ReadRune(); err != nil {
			if err == io.EOF {
				break
			} else {
				logger.Error().Msg(err.Error())
				return false, "", err
			}
		} else {
			limit = append(limit, string(c))
			size += sz
		}

		if len(limit) > limitMax {
			break
		}
	}
	prefix := strings.Join(limit, "")
	for _, v := range commonJSONMultiLineHeaders {
		if strings.HasPrefix(prefix, v) {
			return true, v, nil
		}
	}
	return false, "", err
}

func ParseMultiLineJSONHeaders(file string, prefix string, fullParse bool) []string {
	f, err := os.Open(file)
	defer f.Close()
	if err != nil {
	}
	//r := bufio.NewReader(f)
	headers := make([]string, 0)
	r, rerr := helpers.BufferFromFile(f)
	if rerr != nil {
		return headers
	}
	headersize := len([]rune(prefix))
	currentSize := 0
	//currrentToken := make([]string, 0)
	openCount := 0
	closeCount := 0
	currentBlob := ""
	skipNext := false
	eventCount := 0
	oldlen := 0
	repeated := 0
	oldEventCount := 0
	for {
		if repeated >= 10000 {
			break
		}
		if openCount == closeCount && strings.TrimSpace(currentBlob) != "" {
			// JSON Blob Unmarshall and reset
			//fmt.Printf("EventCount: %v, OpenCount: %v, CloseCount %v, Current: %v \n", eventCount, openCount, closeCount, currentBlob)
			//fmt.Printf("EventCount: %v \n", eventCount)
			eventCount += 1
			openCount = 0
			closeCount = 0
			repeated = 0
			skipNext = true
			var result map[string]any
			jsonErr := json.Unmarshal([]byte(currentBlob), &result)
			if jsonErr != nil {
				//fmt.Printf("test2%vtest\n", currentBlob)
				//fmt.Printf("ERROR PARSING: %v\n", currentBlob)
			}
			//fmt.Println(currentBlob)

			for k, v := range result {
				headers = parseDeepJSONKeys("", k, v, headers)
			}
			currentBlob = ""
			if fullParse {
				continue
			} else {
				// TODO error handling
				break
			}
		}
		c, sz, rerr := r.ReadRune()
		if oldEventCount == eventCount {
			repeated += 1
		}
		oldEventCount = eventCount
		if rerr != nil {
			break
		}
		if skipNext {
			// Skip character in-between blobs - assuming we have concatenated fields
			// This won't work for pretty-printed JSON blobs
			skipNext = false
			continue
		}
		if currentSize < headersize {
			// Skip header
			currentSize += sz
			continue
		}
		if string(c) == "{" {
			openCount += 1
		} else if string(c) == "}" {
			closeCount += 1
		}
		currentBlob += string(c)
		if oldlen == len(currentBlob) {
			// blob is not growing - we are done reading the file.
			break
		}
		oldlen = len(currentBlob)
	}
	//fmt.Printf("Events Detected: %v\n", eventCount)
	//fmt.Println(headers)
	headers = append(headers, vars.ExtraKeysColumnName)
	return headers
}

func ParseMultiLineJSON(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, domainDB maxminddb.Reader, arguments map[string]any, inputFile string, outputFile string, tempArgs map[string]any, jsonkeys []string, prefix string) error {

	inputF, err := helpers.OpenInput(inputFile)
	defer inputF.Close()
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	outputF, err := helpers.CreateOutput(outputFile)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	writer := csv.NewWriter(outputF)
	headers := make([]string, 0)
	headers = append(headers, jsonkeys...)

	// Sort JSONKeys alphabetically
	//sort.Sort(sort.StringSlice(headers))

	headers = helpers.GetHeaders(tempArgs, headers)
	err = writer.Write(headers)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}

	//r := bufio.NewReader(inputF)
	r, rerr := helpers.BufferFromFile(inputF)
	if rerr != nil {
		return rerr
	}

	// For parsing the file rune by rune
	headersize := len([]rune(prefix))
	currentSize := 0
	openCount := 0
	closeCount := 0
	currentBlob := ""
	skipNext := false
	eventCount := 0
	oldlen := 0
	repeated := 0
	oldEventCount := 0

	var fileWG lbtypes.WaitGroupCount
	maxRoutinesPerFile := arguments["maxgoperfile"].(int)
	lineBatchSize := arguments["batchsize"].(int)
	jobTracker := lbtypes.RunningJobs{
		JobCount: 0,
		Mw:       sync.RWMutex{},
	}
	records := make([][]string, 0)
	recordChannel := make(chan []string)
	var writeWG lbtypes.WaitGroupCount
	go helpers.ListenOnWriteChannel(recordChannel, writer, logger, outputF, arguments["writebuffer"].(int), &writeWG)
	// TODO - setup IP address column detection based on provided column name to allow more flexibility in specifying column rather than only regex

	for {
		if repeated >= 10000 {
			break
		}
		if openCount == closeCount && strings.TrimSpace(currentBlob) != "" {
			// JSON Blob Unmarshall and reset
			//fmt.Printf("EventCount: %v, OpenCount: %v, CloseCount %v, Current: %v \n", eventCount, openCount, closeCount, currentBlob)
			//fmt.Printf("EventCount: %v \n", eventCount)
			eventCount += 1
			openCount = 0
			closeCount = 0
			repeated = 0
			skipNext = true
			var result map[string]any
			jsonErr := json.Unmarshal([]byte(currentBlob), &result)
			if jsonErr != nil {
				//fmt.Printf("test2%vtest\n", currentBlob)
				//fmt.Printf("ERROR PARSING: %v\n", currentBlob)
			} else {
				keymap, _ := parseJSONtoMap(currentBlob)
				record := make([]string, len(jsonkeys))
				tmpExtra := ""
				for k, v := range keymap {
					record, tmpExtra = buildDeepRecordJSON("", k, v, headers, record, tmpExtra)
				}
				extraIndex := helpers.FindTargetIndexInSlice(headers, vars.ExtraKeysColumnName)
				if extraIndex != -1 {
					record[extraIndex] += tmpExtra
				}
				/*				if len(record) >= len(headers) {
									trimmedRecord := record[:len(headers)-len(geoFields)]
									records = append(records, trimmedRecord)
								} else {
									records = append(records, record)
								}*/
				records = append(records, record)
				if len(records) >= lineBatchSize {
					if jobTracker.GetJobs() >= maxRoutinesPerFile {
					waitForOthers:
						for {
							if jobTracker.GetJobs() >= maxRoutinesPerFile {
								continue
							} else {
								fileWG.Add(1)
								jobTracker.AddJob()
								go helpers.ProcessRecords(logger, records, asnDB, cityDB, countryDB, domainDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, -1)
								break waitForOthers
							}
						}
					} else {
						fileWG.Add(1)
						jobTracker.AddJob()
						go helpers.ProcessRecords(logger, records, asnDB, cityDB, countryDB, domainDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, -1)
					}
					records = nil
				}

			}
			// Build Record and Send for enrichment
			currentBlob = ""
		}
		c, sz, rerr := r.ReadRune()
		if oldEventCount == eventCount {
			repeated += 1
		}
		oldEventCount = eventCount
		if rerr != nil {
			break
		}
		if skipNext {
			// Skip character in-between blobs - assuming we have concatenated fields
			// This won't work for pretty-printed JSON blobs
			skipNext = false
			continue
		}
		if currentSize < headersize {
			// Skip header
			currentSize += sz
			continue
		}
		if string(c) == "{" {
			openCount += 1
		} else if string(c) == "}" {
			closeCount += 1
		}
		currentBlob += string(c)
		if oldlen == len(currentBlob) {
			// blob is not growing - we are done reading the file.
			break
		}
		oldlen = len(currentBlob)
	}
	fileWG.Add(1)
	// Catchall in case there are still records to process
	jobTracker.AddJob()
	go helpers.ProcessRecords(logger, records, asnDB, cityDB, countryDB, domainDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, -1)
	helpers.CloseChannelWhenDone(recordChannel, &fileWG)
	writeWG.Wait()
	return nil
}

func parseDeepJSONKeys(startingKey string, k string, v any, headers []string) []string {
	if startingKey != "" {
		// As we go down into potential nested letters, we retain this
		k = fmt.Sprintf("%v_%v", startingKey, k)
	}
	switch vv := v.(type) {
	case string:
		if helpers.FindTargetIndexInSlice(headers, k) == -1 {
			headers = append(headers, k)
		}
	case float64:
		if helpers.FindTargetIndexInSlice(headers, k) == -1 {
			headers = append(headers, k)
		}
	case []interface{}:
		if helpers.FindTargetIndexInSlice(headers, k) == -1 {
			headers = append(headers, k)
		}
	case bool:
		if helpers.FindTargetIndexInSlice(headers, k) == -1 {
			headers = append(headers, k)
		}
	case map[string]interface{}:
		for i, vvv := range vv {
			_, ok := vvv.(map[string]interface{})
			if ok {
				headers = parseDeepJSONKeys(k, i, vvv, headers)
			}
			_, ok2 := vvv.(map[string]any)
			if ok2 {
				headers = parseDeepJSONKeys(k, i, vvv, headers)
			}
			if !ok && !ok2 {
				i = fmt.Sprintf("%v_%v", k, i)
				if helpers.FindTargetIndexInSlice(headers, i) == -1 {
					headers = append(headers, i)
				}
			}
		}
	default:
		if helpers.FindTargetIndexInSlice(headers, k) == -1 {
			headers = append(headers, k)
		}
	}
	return headers
}

func buildDeepRecordJSON(startingKey string, k string, v any, headers []string, record []string, tmpExtra string) ([]string, string) {
	if startingKey != "" {
		// As we go down into potential nested letters, we retain this
		k = fmt.Sprintf("%v_%v", startingKey, k)
	}
	switch vv := v.(type) {
	case string:
		headerIndex := helpers.FindTargetIndexInSlice(headers, k)
		if headerIndex == -1 {
			tmpExtra += fmt.Sprintf("%v:%v, ", k, v.(string))
			break
		}
		record[headerIndex] = v.(string)
	case float64:
		headerIndex := helpers.FindTargetIndexInSlice(headers, k)
		if headerIndex == -1 {
			tmpExtra += fmt.Sprintf("%v:%v, ", k, strconv.FormatFloat(v.(float64), 'E', -1, 64))
			break
		}
		record[headerIndex] = strconv.FormatFloat(v.(float64), 'E', -1, 64)
	case []interface{}:
		headerIndex := helpers.FindTargetIndexInSlice(headers, k)
		s := make([]string, len(vv))
		for i, u := range vv {
			s[i] = fmt.Sprint(u)
		}
		if headerIndex == -1 {
			tmpExtra += fmt.Sprintf("%v:%v, ", k, s)
			break
		}
		record[headerIndex] = fmt.Sprint(s)
	case bool:
		headerIndex := helpers.FindTargetIndexInSlice(headers, k)
		if headerIndex == -1 {
			tmpExtra += fmt.Sprintf("%v:%v, ", k, strconv.FormatBool(v.(bool)))
			break
		}
		record[headerIndex] = strconv.FormatBool(v.(bool))
	case map[string]interface{}:
		for kk, uu := range vv {
			_, ok := uu.(map[string]interface{})
			if ok {
				record, tmpExtra = buildDeepRecordJSON(k, kk, uu, headers, record, tmpExtra)
			}
			_, ok2 := uu.(map[string]any)
			if ok2 {
				record, tmpExtra = buildDeepRecordJSON(k, kk, uu, headers, record, tmpExtra)
			}
			if !ok && !ok2 {
				i := fmt.Sprintf("%v_%v", k, kk)
				headerIndex := helpers.FindTargetIndexInSlice(headers, i)
				if headerIndex == -1 {
					tmpExtra += fmt.Sprintf("%v:%v, ", i, uu)
				} else {
					record[headerIndex] = fmt.Sprint(uu)
				}
			}

		}
	default:
		tmpExtra += fmt.Sprintf("%v:%v, ", k, v)
	}
	return record, tmpExtra
}
