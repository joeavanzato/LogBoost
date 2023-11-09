package main

import (
	"encoding/csv"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io"
	"os"
	"strings"
	"sync"
)

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
	scanner, err := scannerFromFile(f)
	if err != nil {
		return false, fields, "", err
	}
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

func parseIISStyle(logger zerolog.Logger, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, domainDB maxminddb.Reader, headers []string, delim string, arguments map[string]any, inputFile string, outputFile string, tempArgs map[string]any) error {
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
	dateindex := -1
	if tempArgs["datecol"].(string) != "" {
		dateindex = findTargetIndexInSlice(headers, arguments["datecol"].(string))
	}

	if !tempArgs["passthrough"].(bool) {
		headers = append(headers, geoFields...)
	}
	err = writer.Write(headers)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	idx := 0
	scanner, err := scannerFromFile(inputF)
	if err != nil {
		return err
	}
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
	var writeWG WaitGroupCount
	go listenOnWriteChannel(recordChannel, writer, logger, outputF, arguments["writebuffer"].(int), &writeWG)
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
			go processRecords(logger, records, asnDB, cityDB, countryDB, domainDB, ipAddressColumn, -1, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
			records = nil
			break
		} else if scanErr != nil {
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
						go processRecords(logger, records, asnDB, cityDB, countryDB, domainDB, ipAddressColumn, -1, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
						break waitForOthers
					}
				}
			} else {
				fileWG.Add(1)
				jobTracker.AddJob()
				go processRecords(logger, records, asnDB, cityDB, countryDB, domainDB, ipAddressColumn, -1, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
			}
			records = nil
		}
		idx += 1
	}
	fileWG.Add(1)
	// Catchall in case there are still records to process
	jobTracker.AddJob()
	go processRecords(logger, records, asnDB, cityDB, countryDB, domainDB, ipAddressColumn, -1, arguments["regex"].(bool), arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
	closeChannelWhenDone(recordChannel, &fileWG)
	writeWG.Wait()
	return nil
}
