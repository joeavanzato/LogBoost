package main

import (
	"encoding/csv"
	"encoding/json"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io"
	"strings"
	"sync"
)

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

	dateindex := -1
	if arguments["datecol"].(string) != "" {
		dateindex = findTargetIndexInSlice(headers, arguments["datecol"].(string))
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
	var writeWG WaitGroupCount
	go listenOnWriteChannel(recordChannel, newWrite, logger, NewOutputF, arguments["writebuffer"].(int), &writeWG)
	for {
		record, Ferr := newParse.Read()

		if Ferr == io.EOF {
			fileWG.Add(1)
			jobTracker.AddJob()
			go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, -1, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
			records = nil
			break
		} else if Ferr != nil {
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
						go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, jsonColumn, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
						break waitForOthers
					}
				}
			} else {
				fileWG.Add(1)
				jobTracker.AddJob()
				go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, jsonColumn, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
			}
			records = nil
		}
		idx += 1
	}
	fileWG.Add(1)
	jobTracker.AddJob()
	go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, jsonColumn, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
	records = nil
	closeChannelWhenDone(recordChannel, &fileWG)
	writeWG.Wait()
}
