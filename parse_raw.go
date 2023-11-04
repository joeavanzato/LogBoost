package main

import (
	"encoding/csv"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io"
	"strings"
	"sync"
)

func parseRaw(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, arguments map[string]any, inputFile string, outputFile string, tempArgs map[string]any) error {
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
	headers = append(headers, "line")
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
		records = append(records, []string{line})
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
