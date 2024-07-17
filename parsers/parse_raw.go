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

func ParseRaw(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, domainDB maxminddb.Reader, arguments map[string]any, inputFile string, outputFile string, tempArgs map[string]any) error {
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
	headers = append(headers, "line")
	headers = append(headers, vars.GeoFields...)
	if tempArgs["use_ti"].(bool) {
		headers = append(headers, vars.ThreatFields...)
	}
	if tempArgs["use_dns"].(bool) {
		headers = append(headers, vars.DNSFields...)
	}
	if tempArgs["use_whois"].(bool) {
		if tempArgs["use_dns"].(bool) {
			headers = append(headers, vars.WhoisDomainFields...)
		}
		headers = append(headers, vars.WhoisIPFields...)
	}
	if tempArgs["use_idb"].(bool) {
		headers = append(headers, vars.IDBFields...)
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
			//return scanErr
			continue
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
