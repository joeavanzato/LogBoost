package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

func checkJSON(logger zerolog.Logger, file string) (bool, []string, error) {
	// Check if we can successfully unmarshall the first line of the file - if yes, we assume it is JSON-per-line based logging
	f, err := os.Open(file)
	keys := make([]string, 0)
	defer f.Close()
	if err != nil {
		return false, keys, err
	}
	scanner, err := scannerFromFile(f)
	if err != nil {
		return false, keys, err
	}
	for {
		if scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			//fmt.Println(line)
			scanErr := scanner.Err()
			if scanErr == io.EOF {
				if len(keys) == 0 {
					return false, keys, err
				}
				break
			}
			if scanErr != nil {
				return false, keys, err
			}
			var result map[string]any
			jsonErr := json.Unmarshal([]byte(line), &result)
			if jsonErr != nil {
				return false, keys, jsonErr
			}
			for k, _ := range result {
				if findTargetIndexInSlice(keys, k) == -1 {
					keys = append(keys, k)
				}
			}
		} else {
			break
		}
	}
	return true, keys, nil
}

func parseJSON(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, arguments map[string]any, inputFile string, outputFile string, tempArgs map[string]any, jsonkeys []string) error {
	inputF, err := openInput(inputFile)
	defer inputF.Close()
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	outputF, err := createOutput(outputFile)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	writer := csv.NewWriter(outputF)
	headers := make([]string, 0)
	headers = append(headers, jsonkeys...)
	headers = append(headers, geoFields...)
	err = writer.Write(headers)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	scanner, err := scannerFromFile(inputF)
	if err != nil {
		return err
	}
	var fileWG WaitGroupCount
	maxRoutinesPerFile := arguments["maxgoperfile"].(int)
	lineBatchSize := arguments["batchsize"].(int)
	jobTracker := runningJobs{
		JobCount: 0,
		mw:       sync.RWMutex{},
	}
	records := make([][]string, 0)
	recordChannel := make(chan []string)
	go listenOnWriteChannel(recordChannel, writer, logger, outputF, arguments["writebuffer"].(int))
	idx := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if len(line) == 0 {
			continue
		}
		scanErr := scanner.Err()
		if scanErr == io.EOF {
			fileWG.Add(1)
			jobTracker.AddJob()
			go processRecords(logger, records, asnDB, cityDB, countryDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, -1)
			records = nil
			break
		}
		if scanErr != nil {
			logger.Error().Msg(scanErr.Error())
			return scanErr
		}
		record := buildRecordJSON(line, jsonkeys)
		if len(record) == 0 {
			// Error parsing or nothing to parse
			continue
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
						go processRecords(logger, records, asnDB, cityDB, countryDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, -1)
						break waitForOthers
					}
				}
			} else {
				fileWG.Add(1)
				jobTracker.AddJob()
				go processRecords(logger, records, asnDB, cityDB, countryDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, -1)
			}
			records = nil
		}
		idx += 1
	}
	fileWG.Add(1)
	// Catchall in case there are still records to process
	jobTracker.AddJob()
	go processRecords(logger, records, asnDB, cityDB, countryDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, -1)
	closeChannelWhenDone(recordChannel, &fileWG)
	return nil
}

func parseJSONtoMap(input string) (map[string]any, error) {
	var result map[string]any
	jsonErr := json.Unmarshal([]byte(input), &result)
	if jsonErr != nil {
		return make(map[string]any), jsonErr
	}
	return result, nil
}

func buildRecordJSON(line string, jsonKeys []string) []string {
	keymap, err := parseJSONtoMap(line)
	if err != nil {
		return make([]string, 0)
	}
	tempRecord := make([]string, len(jsonKeys))

	for k, v := range keymap {
		headerIndex := findTargetIndexInSlice(jsonKeys, k)
		if headerIndex == -1 {
			// Error - could not find a key in the headers so we will skip it - should never happen since we use the same parsing logic both runs.
			continue
		}
		switch vv := v.(type) {
		case string:
			tempRecord[headerIndex] = v.(string)
		case float64:
			tempRecord[headerIndex] = strconv.FormatFloat(v.(float64), 'E', -1, 64)
		case []interface{}:
			s := make([]string, len(vv))
			for i, u := range vv {
				s[i] = fmt.Sprint(u)
			}
			tempRecord[headerIndex] = fmt.Sprint(s)
		case bool:
			tempRecord[headerIndex] = strconv.FormatBool(v.(bool))
		case map[string]interface{}:
			s := make(map[string]string, len(vv))
			for kk, uu := range vv {
				s[kk] = fmt.Sprint(uu)
			}
			tempRecord[headerIndex] = fmt.Sprint(s)
		default:
			fmt.Println(v)
		}
	}
	return tempRecord
}
