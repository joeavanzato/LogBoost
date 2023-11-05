package main

import (
	"encoding/csv"
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
)

var kv_equals_base = regexp.MustCompile(`(?P<key>[^=\s]+)=\"{0,1}(?P<value>[^,]+)\"{0,1},?`)

func checkKV(logger zerolog.Logger, file string, arguments map[string]any) (bool, []string, error) {
	regex_ := fmt.Sprintf(`(?P<key>[^%v\s]+)%v\"{0,1}(?P<value>[^%v]+)\"{0,1}%v?`, arguments["separator"].(string), arguments["separator"].(string), arguments["delimiter"].(string), arguments["delimiter"].(string))
	kv_regex := regexp.MustCompile(regex_)
	f, err := os.Open(file)
	headers := make([]string, 0)
	defer f.Close()
	if err != nil {
		return false, headers, err
	}
	scanner, err := scannerFromFile(f)
	if err != nil {
		return false, headers, err
	}
	fullparse := arguments["fullparse"].(bool)
	// If fullparse, then we will scan entire file for keys - otherwise, we will only use the keys present in the first record - any 'extra' keys will be stored in EXTRA_KEYS
	for {
		if scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			scanErr := scanner.Err()
			if scanErr == io.EOF {
				fmt.Println("END")
				if len(headers) == 0 {
					return false, headers, nil
				} else {
					break
				}
			} else if scanErr != nil {
				return false, headers, nil
			}
			match := kv_regex.FindAllStringSubmatch(line, -1)
			if match == nil {
				return false, headers, nil
			}
			for _, v := range match {
				// each object is length of 3 -match content, key then value - so v[1] represents the 'key'
				if findTargetIndexInSlice(headers, v[1]) == -1 {
					headers = append(headers, v[1])
				}
			}

			if fullparse {
				continue
			} else {
				headers = append(headers, extraKeysColumnName)
				return true, headers, nil
			}
		} else {
			break
		}
	}
	return true, headers, nil
}

func parseKV(logger zerolog.Logger, inputFile string, outputFile string, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, arguments map[string]any, tempArgs map[string]any, kvheaders []string) error {
	// If full parse, then we will do similar to JSON/CEF dynamic insertion
	// otherwise, we will only use columns that exist on the first line and everything else will be shoved into a string under var named extra_column - the last line of the current headers
	// boilerplate
	regex_ := fmt.Sprintf(`(?P<key>[^%v\s]+)%v\"{0,1}(?P<value>[^%v]+)\"{0,1}%v?`, arguments["separator"].(string), arguments["separator"].(string), arguments["delimiter"].(string), arguments["delimiter"].(string))
	kv_regex := regexp.MustCompile(regex_)
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
	headers = append(headers, kvheaders...)
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
	var writeWG WaitGroupCount
	go listenOnWriteChannel(recordChannel, writer, logger, outputF, arguments["writebuffer"].(int), &writeWG)
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
		record := buildKVRecord(line, kvheaders, kv_regex)
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
	writeWG.Wait()
	return nil
}

func buildKVRecord(line string, kvheaders []string, regex *regexp.Regexp) []string {
	tempRecord := make([]string, len(kvheaders))
	match := regex.FindAllStringSubmatch(line, -1)
	if len(match) == 0 {
		return make([]string, 0)
	}
	tmpExtra := ""
	for _, v := range match {
		headerIndex := findTargetIndexInSlice(kvheaders, v[1])
		if !strings.HasPrefix(v[2], "\"") && strings.HasSuffix(v[2], "\"") {
			v[2] = strings.TrimSuffix(v[2], "\"")
		}
		if headerIndex == -1 {
			tmpExtra += fmt.Sprintf("%v=%v, ", v[1], v[2])
		} else {
			tempRecord[headerIndex] = v[2]
		}
	}
	extraIndex := findTargetIndexInSlice(kvheaders, extraKeysColumnName)
	if extraIndex != -1 {
		tempRecord[extraIndex] = tmpExtra
	}
	return tempRecord
}