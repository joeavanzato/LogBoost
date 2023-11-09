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

var commonFormat = regexp.MustCompile(`(?P<client>.*?)\s(?P<identity>.*?)\s(?P<user>.*?)\s\[(?P<timestamp>.*?)\]\s\"(?P<httpmethod>.*?)\s(?P<httpresource>.*?)\s(?P<httpversion>.*?)\"\s(?P<httpstatus>.*?)\s(?P<bytes>.*)`)
var combinedFormat = regexp.MustCompile(`(?P<client>.*?)\s(?P<identity>.*?)\s(?P<user>.*?)\s\[(?P<timestamp>.*?)\]\s\"(?P<httpmethod>.*?)\s(?P<httpresource>.*?)\s(?P<httpversion>.*?)\"\s(?P<httpstatus>.*?)\s(?P<bytes>.*?)\s\"(?P<referer>.*?)\"\s\"(?P<useragent>.*)\"`)

func checkCLF(logger zerolog.Logger, file string) (int, error) {
	// We will check for both Common Log Format and Combined Log Format style logs here - both are similar but Combined has two extra fields - referer and user agent
	// Common Log Format: host ident authuser date "request" status bytes
	// Combined Log Format: host ident authuser date "request" status bytes "referer" "useragent"
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
			if combinedFormat.MatchString(line) {
				return 1, nil
			} else if commonFormat.MatchString(line) {
				return 0, nil
			} else {
				return -1, nil
			}
		}
	}
}

func parseCLF(logger zerolog.Logger, inputFile string, outputFile string, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, domainDB maxminddb.Reader, arguments map[string]any, tempArgs map[string]any, format int) error {
	commonHeaders := []string{"CLIENT", "ID", "USER", "TIMESTAMP", "METHOD", "RESOURCE", "VERSION", "STATUS", "BYTES"}
	combinedHeaders := []string{"REFERER", "USER AGENT"}
	inputF, err := openInput(inputFile)
	defer inputF.Close()
	if err != nil {
		return err
	}
	headers := make([]string, 0)
	headers = append(headers, commonHeaders...)
	if format == 1 {
		headers = append(headers, combinedHeaders...)
	}

	if !tempArgs["passthrough"].(bool) {
		headers = append(headers, geoFields...)
	}
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
		// Should just set this to fixed '3' since it always is
		dateindex = findTargetIndexInSlice(headers, "TIMESTAMP")
	}
	// TODO - Allow IP address column specification
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
			go processRecords(logger, records, asnDB, cityDB, countryDB, domainDB, 0, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
			records = nil
			break
		} else if scanErr != nil {
			logger.Error().Msg(scanErr.Error())
			return scanErr
		}
		record := buildCLFRecord(line, format)
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
						go processRecords(logger, records, asnDB, cityDB, countryDB, domainDB, 0, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
						break waitForOthers
					}
				}
			} else {
				fileWG.Add(1)
				jobTracker.AddJob()
				go processRecords(logger, records, asnDB, cityDB, countryDB, domainDB, 0, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
			}
			records = nil
		}
		idx += 1
	}
	fileWG.Add(1)
	jobTracker.AddJob()
	go processRecords(logger, records, asnDB, cityDB, countryDB, domainDB, 0, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
	closeChannelWhenDone(recordChannel, &fileWG)
	writeWG.Wait()
	return nil
}

func buildCLFRecord(line string, format int) []string {
	match := make([]string, 0)
	if format == 0 {
		match = commonFormat.FindStringSubmatch(line)
	} else if format == 1 {
		match = combinedFormat.FindStringSubmatch(line)
	}
	if len(match) == 0 {
		return match
	} else {
		return match[1:]
	}
}
