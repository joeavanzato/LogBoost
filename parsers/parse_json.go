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

func CheckJSON(logger zerolog.Logger, file string, fullParse bool) (bool, []string, error) {
	// Check if we can successfully unmarshall the first line of the file - if yes, we assume it is JSON-per-line based logging
	f, err := os.Open(file)
	keys := make([]string, 0)
	defer f.Close()
	if err != nil {
		return false, keys, err
	}
	scanner, err := helpers.ScannerFromFile(f)
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
			for k, v := range result {
				keys = parseDeepJSONKeys("", k, v, keys)
			}
			// Old method - 'shallow'

			/*			for k, _ := range result {
						if findTargetIndexInSlice(keys, k) == -1 {
							keys = append(keys, k)
						}
					}*/

			if fullParse {
				continue
			} else {
				keys = append(keys, vars.ExtraKeysColumnName)
				return true, keys, nil
			}

		} else {
			break
		}
	}
	if len(keys) == 0 {
		return false, keys, nil
	}
	return true, keys, nil
}

func ParseJSON(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, domainDB maxminddb.Reader, arguments map[string]any, inputFile string, outputFile string, tempArgs map[string]any, jsonkeys []string) error {
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
	//sort.Sort(sort.StringSlice(headers))
	if !arguments["passthrough"].(bool) {
		headers = append(headers, vars.GeoFields...)
	}
	err = writer.Write(headers)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	scanner, err := helpers.ScannerFromFile(inputF)
	if err != nil {
		return err
	}
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
			go helpers.ProcessRecords(logger, records, asnDB, cityDB, countryDB, domainDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, -1)
			records = nil
			break
		}
		if scanErr != nil {
			logger.Error().Msg(scanErr.Error())
			return scanErr
		}
		// Old method
		//record := buildRecordJSON(line, jsonkeys)
		keymap, _ := parseJSONtoMap(line)
		record := make([]string, len(jsonkeys))
		tmpExtra := ""
		for k, v := range keymap {
			record, tmpExtra = buildDeepRecordJSON("", k, v, headers, record, tmpExtra)
		}
		extraIndex := helpers.FindTargetIndexInSlice(headers, vars.ExtraKeysColumnName)
		if extraIndex != -1 {
			record[extraIndex] += tmpExtra
		}

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
		idx += 1
	}
	fileWG.Add(1)
	// Catchall in case there are still records to process
	jobTracker.AddJob()
	go helpers.ProcessRecords(logger, records, asnDB, cityDB, countryDB, domainDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, -1)
	helpers.CloseChannelWhenDone(recordChannel, &fileWG)
	writeWG.Wait()
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
	tmpExtra := ""

	for k, v := range keymap {
		headerIndex := helpers.FindTargetIndexInSlice(jsonKeys, k)
		/*		if headerIndex == -1 {
				continue
			}*/
		switch vv := v.(type) {
		case string:
			if headerIndex == -1 {
				tmpExtra += fmt.Sprintf("%v:%v, ", k, v.(string))
				continue
			}
			tempRecord[headerIndex] = v.(string)
		case float64:
			if headerIndex == -1 {
				tmpExtra += fmt.Sprintf("%v:%v, ", k, strconv.FormatFloat(v.(float64), 'E', -1, 64))
				continue
			}
			tempRecord[headerIndex] = strconv.FormatFloat(v.(float64), 'E', -1, 64)
		case []interface{}:
			s := make([]string, len(vv))
			for i, u := range vv {
				s[i] = fmt.Sprint(u)
			}
			if headerIndex == -1 {
				tmpExtra += fmt.Sprintf("%v:%v, ", k, s)
				continue
			}
			tempRecord[headerIndex] = fmt.Sprint(s)
		case bool:
			if headerIndex == -1 {
				tmpExtra += fmt.Sprintf("%v:%v, ", k, strconv.FormatBool(v.(bool)))
				continue
			}
			tempRecord[headerIndex] = strconv.FormatBool(v.(bool))
		case map[string]interface{}:
			s := make(map[string]string, len(vv))
			for kk, uu := range vv {
				s[kk] = fmt.Sprint(uu)
			}
			if headerIndex == -1 {
				tmpExtra += fmt.Sprintf("%v:%v, ", k, s)
				continue
			}
			tempRecord[headerIndex] = fmt.Sprint(s)
		default:
			r := fmt.Sprintf("Error: Unhandled Type: %v", v)
			fmt.Println(r)
		}
	}
	extraIndex := helpers.FindTargetIndexInSlice(jsonKeys, vars.ExtraKeysColumnName)
	if extraIndex != -1 {
		tempRecord[extraIndex] = tmpExtra
	}
	return tempRecord
}
