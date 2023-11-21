package parsers

import (
	"encoding/csv"
	"github.com/joeavanzato/logboost/helpers"
	"github.com/joeavanzato/logboost/lbtypes"
	"github.com/joeavanzato/logboost/vars"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io"
	"strings"
	"sync"
)

func setupHeaders(logger zerolog.Logger, arguments map[string]any, parser *csv.Reader, writer *csv.Writer) (int, int, []string, []string, error) {
	// If flat CSV with no JSON, write the original headers plus new ones for the geo attributes
	// If JSON field with flatten option, write original headers, then embedded JSON headers then geo attributes
	// returns ints representing which column index in original data represents either the straight IP Address as well as JSON - -1 if does not exist.
	idx := 0
	ipAddressColumn := -1
	jsonColumn := -1
	headers := make([]string, 0)
	jsonKeys := make([]string, 0)
	for {
		record, err := parser.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return ipAddressColumn, jsonColumn, headers, nil, err
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
		}
		// TODO - Allow shallow-parse for CSVs
		if jsonColumn != -1 && arguments["fullparse"].(bool) {
			keymap, err := parseJSONtoMap(record[jsonColumn])
			if err != nil {
				continue
			}
			/*			for k, _ := range keymap {
						if findTargetIndexInSlice(jsonKeys, k) == -1 {
							jsonKeys = append(jsonKeys, k)
						}
					}*/
			for k, v := range keymap {
				jsonKeys = parseDeepJSONKeys("", k, v, jsonKeys)
			}
		} else {
			break
		}
	}

	// Add Geo fields to current header setup
	if jsonColumn != -1 {
		headers = append(headers, jsonKeys...)
		headers = append(headers, vars.ExtraKeysColumnName)
	}
	if !arguments["passthrough"].(bool) {
		headers = append(headers, vars.GeoFields...)
	}
	return ipAddressColumn, jsonColumn, headers, jsonKeys, nil
}

func ProcessCSV(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, domainDB maxminddb.Reader, arguments map[string]any, inputFile string, outputFile string, tempArgs map[string]any) {
	parser, writer, inputF1, _, err := helpers.GetNewPW(logger, inputFile, outputFile)
	defer inputF1.Close()
	if err != nil {
		return
	}
	ipAddressColumn, jsonColumn, headers, jsonKeys, err := setupHeaders(logger, arguments, parser, writer)
	if err != nil {
		logger.Error().Msgf("Error Processing File: %v", err.Error())
		return
	}

	newParse, newWrite, NewInputF, NewOutputF, err := helpers.GetNewPW(logger, inputFile, outputFile)
	defer NewInputF.Close()
	if err != nil {
		return
	}

	dateindex := -1
	if arguments["datecol"].(string) != "" {
		dateindex = helpers.FindTargetIndexInSlice(headers, arguments["datecol"].(string))
	}

	idx := 0
	var fileWG lbtypes.WaitGroupCount
	recordChannel := make(chan []string)
	maxRoutinesPerFile := arguments["maxgoperfile"].(int)
	lineBatchSize := arguments["batchsize"].(int)
	jobTracker := lbtypes.RunningJobs{
		JobCount: 0,
		Mw:       sync.RWMutex{},
	}
	records := make([][]string, 0)
	var writeWG lbtypes.WaitGroupCount
	go helpers.ListenOnWriteChannel(recordChannel, newWrite, logger, NewOutputF, arguments["writebuffer"].(int), &writeWG)
	for {
		record, Ferr := newParse.Read()
		if Ferr == io.EOF {
			fileWG.Add(1)
			jobTracker.AddJob()
			go helpers.ProcessRecords(logger, records, asnDB, cityDB, countryDB, domainDB, ipAddressColumn, jsonColumn, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
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

		if jsonColumn != -1 && arguments["fullparse"].(bool) {
			tmpRecord := make([]string, len(jsonKeys))
			/*			jsonData := buildRecordJSON(record[jsonColumn], jsonKeys)
						record = append(record, jsonData...)*/
			keymap, _ := parseJSONtoMap(record[jsonColumn])
			if len(jsonKeys) == 0 {
				//TODO
			}
			tmpExtra := ""
			for k, v := range keymap {
				tmpRecord, tmpExtra = buildDeepRecordJSON("", k, v, jsonKeys, tmpRecord, tmpExtra)
			}
			extraIndex := helpers.FindTargetIndexInSlice(headers, vars.ExtraKeysColumnName)
			record = append(record, tmpRecord...)
			if extraIndex != -1 {
				record = append(record, tmpExtra)
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
						go helpers.ProcessRecords(logger, records, asnDB, cityDB, countryDB, domainDB, ipAddressColumn, jsonColumn, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
						break waitForOthers
					}
				}
			} else {
				fileWG.Add(1)
				jobTracker.AddJob()
				go helpers.ProcessRecords(logger, records, asnDB, cityDB, countryDB, domainDB, ipAddressColumn, jsonColumn, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
			}
			records = nil
		}
		idx += 1
	}
	fileWG.Add(1)
	jobTracker.AddJob()
	go helpers.ProcessRecords(logger, records, asnDB, cityDB, countryDB, domainDB, ipAddressColumn, jsonColumn, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
	records = nil
	helpers.CloseChannelWhenDone(recordChannel, &fileWG)
	writeWG.Wait()
}
