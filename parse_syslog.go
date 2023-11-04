package main

import (
	"encoding/csv"
	"github.com/oschwald/maxminddb-golang"
	"github.com/rs/zerolog"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
)

var syslog_rfc3164_rex = regexp.MustCompile(`(?P<pri><\d{1,5}>)(?P<timestamp>[A-Za-z]{3}\s\d{2}\s\d{2}:\d{2}:\d{2})\s(?P<syshost>.*?)\s(?P<msg>.*)`)
var syslog_rfc5424_rex = regexp.MustCompile(`(?P<pri><\d{1,5}>)(?P<version>\d{1})\s(?P<timestamp>\d{4}-\d{1,2}-\d{1,2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\s(?P<syshost>.*?)\s(?P<msg>.*)`)
var syslog_generic = regexp.MustCompile(`^(?P<timestamp>[a-zA-Z]{3}\s{1,3}\d{1,2}\s\d{1,2}:\d{2}:\d{2})\s(?P<source>.*?)\s(?P<proc>.*?)\[{0,1}(?P<procid>\d{0,6})\]{0,1}:\s(?P<message>.*)`)

func checkSyslog(logger zerolog.Logger, file string) (int, error) {
	f, err := os.Open(file)
	defer f.Close()
	if err != nil {
		return -1, err
	}

	scanner, err := scannerFromFile(f)
	if err != nil {
		return -1, err
	}
	for {
		if scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			//fmt.Println(line)
			scanErr := scanner.Err()
			if scanErr == io.EOF {
				return -1, err
			}
			if scanErr != nil {
				return -1, err
			}
			if syslog_rfc3164_rex.MatchString(line) {
				return 0, nil
			} else if syslog_rfc5424_rex.MatchString(line) {
				return 1, nil
			} else if syslog_generic.MatchString(line) {
				return 2, nil
			} else {
				return -1, nil
			}
		}
	}
}

func parseSyslog(logger zerolog.Logger, inputFile string, outputFile string, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, arguments map[string]any, tempArgs map[string]any, syslogFormat int) error {
	inputF, err := openInput(inputFile)
	defer inputF.Close()
	if err != nil {
		return err
	}
	headers := make([]string, 0)
	if syslogFormat == 0 {
		// RFC 3164
		headers = append(headers, "PRI", "TIMESTAMP", "HOST", "MESSAGE")
	} else if syslogFormat == 1 {
		// RFC 5424
		headers = append(headers, "PRI", "VERSION", "TIMESTAMP", "HOST", "MESSAGE")
	} else if syslogFormat == 2 {
		// Generic Syslog
		headers = append(headers, "TIMESTAMP", "HOST", "PROCESS", "PROCID", "MESSAGE")
	}

	headers = append(headers, geoFields...)
	outputF, err := createOutput(outputFile)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(outputF)
	err = writer.Write(headers)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	var fileWG WaitGroupCount
	recordChannel := make(chan []string)
	maxRoutinesPerFile := arguments["maxgoperfile"].(int)
	lineBatchSize := arguments["batchsize"].(int)
	jobTracker := runningJobs{
		JobCount: 0,
		mw:       sync.RWMutex{},
	}
	records := make([][]string, 0)
	dateindex := -1
	if tempArgs["datecol"].(string) != "" {
		dateindex = findTargetIndexInSlice(headers, "TIMESTAMP")
	}
	ipAddressColumn := findTargetIndexInSlice(headers, arguments["IPcolumn"].(string))
	var writeWG WaitGroupCount
	go listenOnWriteChannel(recordChannel, writer, logger, outputF, arguments["writebuffer"].(int), &writeWG)
	scanner, err := scannerFromFile(inputF)
	if err != nil {
		return err
	}
	idx := 0
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			break
		}
		scanErr := scanner.Err()
		if scanErr == io.EOF {
			fileWG.Add(1)
			jobTracker.AddJob()
			go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
			records = nil
			break
		} else if scanErr != nil {
			logger.Error().Msg(scanErr.Error())
			return scanErr
		}
		record := buildSyslogRecord(line, syslogFormat)
		if len(record) == 0 {
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
						go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
						break waitForOthers
					}
				}
			} else {
				fileWG.Add(1)
				jobTracker.AddJob()
				go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
			}
			records = nil
		}
		idx += 1
	}
	fileWG.Add(1)
	jobTracker.AddJob()
	go processRecords(logger, records, asnDB, cityDB, countryDB, ipAddressColumn, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
	closeChannelWhenDone(recordChannel, &fileWG)
	writeWG.Wait()
	return nil
}

func buildSyslogRecord(line string, format int) []string {
	match := make([]string, 0)
	if format == 0 {
		match = syslog_rfc3164_rex.FindStringSubmatch(line)
	} else if format == 1 {
		match = syslog_rfc5424_rex.FindStringSubmatch(line)
	} else if format == 2 {
		match = syslog_generic.FindStringSubmatch(line)
	}
	if len(match) == 0 {
		return match
	} else {
		return match[1:]
	}

}
