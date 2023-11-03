package main

import (
	"bufio"
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

//https://docs.nxlog.co/integrate/cef-logging.html
//CEF log syntax
//Jan 11 10:25:39 host CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
//Log sample
//Oct 12 04:16:11 localhost CEF:0|nxlog.org|nxlog|2.7.1243|Executable Code was Detected|Advanced exploit detected|100|src=192.168.255.110 spt=46117 dst=172.25.212.204 dpt=80

var syslog_rfc3164_rex = regexp.MustCompile(`(?P<pri><\d{1,5}>)(?P<timestamp>[A-Za-z]{3}\s\d{2}\s\d{2}:\d{2}:\d{2})\s(?P<syshost>.*?)\s(?P<CEFALL>CEF.*)`)
var syslog_rfc5424_rex = regexp.MustCompile(`(?P<pri><\d{1,5}>)(?P<version>\d{1})\s(?P<timestamp>\d{4}-\d{1,2}-\d{1,2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\s(?P<syshost>.*?)\s(?P<CEFALL>CEF.*)`)

func checkCEF(logger zerolog.Logger, inputFile string, fullParse bool) ([]string, int, error) {
	// Determines if a file is CEF - if so, returns all possible headers
	// Unfortunately, CEF files can have a variable number of key-value pairs - this means that to properly parse to CSV, we have to scan the entire file first to find all possible headers then go back and re-scan for actual content ingestion.
	// the control variable 'fullParse' determines whether we will do this full-scan or not
	// If not, we will just use standard CEF parameters to parse the log and the entire extension will exist on it's own line
	// If yes, then we will parse all extensions in the log once and use as the CSV headers

	// CEF is delivered in multiple formats
	// CEF with NO SYSLOG HEADER
	// <6>CEF:0|FORCEPOINT|Firewall|6.8.5|70019|Connection_Discarded|0|deviceExternalId=NGFW2 node 1 dvchost=10.x.x.149 dvc=10.x.x.149 src=10.x.x.4 dst=10.x.x.255 spt=138 dpt=138 proto=17 deviceInboundInterface=0 act=Discard msg=spoofed packet deviceFacility=Packet Filtering rt=Sep 14 2021 13:58:33 app=NetBIOS Datagram
	// CEF with SYSLOG RFC 3164 HEADER
	// <6>Sep 14 14:12:51 10.x.x.143 CEF:0|FORCEPOINT|Firewall|6.8.6|70018|Connection_Allowed|0|deviceExternalId=NGFW1 node 1 dvchost=10.x.x.143 dvc=10.x.x.143 src=10.x.x.142 dst=20.x.x.209 spt=59358 dpt=443 proto=6 deviceInboundInterface=0 deviceOutboundInterface=1 act=Allow sourceTranslatedAddress=10.x.x.143 destinationTranslatedAddress=20.x.x.209 sourceTranslatedPort=27237 destinationTranslatedPort=443 deviceFacility=Packet Filtering rt=Sep 14 2021 14:12:51 app=HTTPS cs1Label=RuleID cs1=2100123.2 cs2Label=NatRuleId cs2=2099555.1
	// CEF with SYSLOG RFC 5424 HEADER
	//<34>1 2003-10-11T22:14:15.003Z mymachine.example.com CEF:0|FORCEPOINT|Firewall|6.8.6|70018|Connection_Allowed|0|deviceExternalId=NGFW1 node 1 dvchost=10.x.x.143 dvc=10.x.x.143 src=10.x.x.142 dst=20.x.x.209 spt=59358 dpt=443 proto=6 deviceInboundInterface=0 deviceOutboundInterface=1 act=Allow sourceTranslatedAddress=10.x.x.143 destinationTranslatedAddress=20.x.x.209 sourceTranslatedPort=27237 destinationTranslatedPort=443 deviceFacility=Packet Filtering rt=Sep 14 2021 14:12:51 app=HTTPS cs1Label=RuleID cs1=2100123.2 cs2Label=NatRuleId cs2=2099555.1
	// We need to determine which one we are examining in the current file, if any.

	// returns false/true if it is CEF or not
	// returns the full list of possible headers depending on fullParse or not
	// returns 0, 1 or 2 depending on no SYSLOG header, RFC3164 or RFC5424
	// returns err/nil depending

	f, err := os.Open(inputFile)
	defer f.Close()
	// Base Headers for syslog format messages
	syslog_headers := []string{"PRI", "VER", "TIMESTAMP", "HOST"}
	cef_base_headers := []string{"CEF_VERSION", "CEF_VENDOR", "CEF_PRODUCT", "CEF_PRODUCT_VERSION", "CEF_EVENT_ID", "CEF_EVENT_NAME", "CEF_EVENT_SEVERITY"}
	syslog_headers = append(syslog_headers, cef_base_headers...)
	if err != nil {
		return make([]string, 0), -1, nil
	}
	scanner := bufio.NewScanner(f)
	idx := 0
	for {
		if scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			//fmt.Println(line)
			scanErr := scanner.Err()
			if scanErr == io.EOF {
				break
			}
			logFormat, match := identifySyslogHeader(line)
			if len(match) == 0 {
			}
			if logFormat == -1 {
				return make([]string, 0), logFormat, nil
			}

			if !fullParse && idx == 0 {
				// We will only use the first line to try and determine the format/if CEF/etc
				//headers = append(headers, "CEF_MESSAGE")
				if logFormat == 0 {
					cef_base_headers = append(cef_base_headers, "CEF_EXTENSIONS")
					return cef_base_headers, logFormat, nil
				}
				if logFormat == 1 || logFormat == 2 {
					syslog_headers = append(syslog_headers, "CEF_EXTENSIONS")
					return syslog_headers, logFormat, nil
				}
			}
			// If we are doing a full parse, then we will scroll through entire file to find all possible CEF KV Pairs to use as headers
			// TODO
			// If 0, we have to just parse the base CEF - if 1 or 2 we have to first pull it out of the regex match then parse it
			// There are 7 headers + all extensions in a CEF message
			// CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
			cefValues := make([]string, 0)
			if logFormat == 0 {
				cefValues = strings.SplitN(line, "|", 8)
				cef_base_headers = getExtensionKeys(cef_base_headers, strings.TrimSpace(cefValues[len(cefValues)-1]))
			} else {
				cefValues = strings.SplitN(match[len(match)-1], "|", 8)
				cef_base_headers = getExtensionKeys(syslog_headers, strings.TrimSpace(cefValues[len(cefValues)-1]))
			}

			idx += 1
		} else {
			break
		}
	}
	return make([]string, 0), -1, nil
}

func getExtensionKeys(headers []string, input string) []string {
	fmt.Println(input)

	return headers

}

func parseCEF(logger zerolog.Logger, inputFile string, outputFile string, fullParse bool, headers []string, logFormat int, asnDB maxminddb.Reader, cityDB maxminddb.Reader, countryDB maxminddb.Reader, arguments map[string]any, tempArgs map[string]any) error {
	inputF, err := openInput(inputFile)
	defer inputF.Close()
	if err != nil {
		return err
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
	go listenOnWriteChannel(recordChannel, writer, logger, outputF, arguments["writebuffer"].(int))
	scanner := bufio.NewScanner(inputF)
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
			go processRecords(logger, records, asnDB, cityDB, countryDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
			records = nil
			break
		} else if scanErr != nil {
			logger.Error().Msg(scanErr.Error())
			return scanErr
		}
		record := splitCEFLine(line, fullParse, headers, logFormat)
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
						go processRecords(logger, records, asnDB, cityDB, countryDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
						break waitForOthers
					}
				}
			} else {
				fileWG.Add(1)
				jobTracker.AddJob()
				go processRecords(logger, records, asnDB, cityDB, countryDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
			}
			records = nil
		}
		idx += 1
	}
	fileWG.Add(1)
	jobTracker.AddJob()
	go processRecords(logger, records, asnDB, cityDB, countryDB, -1, -1, true, arguments["dns"].(bool), recordChannel, &fileWG, &jobTracker, tempArgs, dateindex)
	closeChannelWhenDone(recordChannel, &fileWG)
	return nil
}

func splitCEFLine(input string, fullParse bool, headers []string, logFormat int) []string {
	if !fullParse {
		if logFormat == 0 {
			cefValues := strings.SplitN(input, "|", 8)
			return cefValues
		}
		if logFormat == 1 {
			match := syslog_rfc3164_rex.FindStringSubmatch(input)
			if len(match) == 0 {
				return make([]string, 0)
			}
			cefValues := strings.SplitN(match[len(match)-1], "|", 8)
			fullValues := make([]string, 0)
			fullValues = append(fullValues, match[1])
			// version 3164 does not have syslog version, so we just insert a blank as second value then resume
			fullValues = append(fullValues, "")
			fullValues = append(fullValues, match[2:len(match)-1]...)
			fullValues = append(fullValues, cefValues...)
			return fullValues
		}
		if logFormat == 2 {
			// Working for normal, standardized CEF syslog
			match := syslog_rfc5424_rex.FindStringSubmatch(input)
			if len(match) == 0 {
				return make([]string, 0)
			}
			cefValues := strings.SplitN(match[len(match)-1], "|", 8)
			fullValues := make([]string, 0)
			fullValues = append(fullValues, match[1:len(match)-1]...)
			fullValues = append(fullValues, cefValues...)
			return fullValues
		}
	}

	return make([]string, 0)
}

func identifySyslogHeader(input string) (int, []string) {
	// -1 == Could not identify as CEF format log
	// 0 == CEF with no Syslog Header
	// 1 == CEF with Syslog RFC 3164
	// 2 == CEF with Syslog RFC 5424
	if strings.HasPrefix(input, "CEF") {
		return 0, nil
	}
	match := syslog_rfc3164_rex.FindStringSubmatch(input)
	if len(match) != 0 {
		return 1, match
	}
	match = syslog_rfc5424_rex.FindStringSubmatch(input)
	if len(match) != 0 {
		return 2, match
	}
	return -1, nil
}
