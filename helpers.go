package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

func setupLogger() zerolog.Logger {
	logFileName := logFile
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		_, err := fmt.Fprintf(os.Stderr, "Couldn't Initialize Log File: %s", err)
		if err != nil {
			panic(nil)
		}
		panic(err)
	}
	cw := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
		FormatLevel: func(i interface{}) string {
			return strings.ToUpper(fmt.Sprintf("[%s]", i))
		},
	}
	cw.NoColor = true
	mw := io.MultiWriter(cw, logFile)
	logger := zerolog.New(mw).Level(zerolog.TraceLevel)
	logger = logger.With().Timestamp().Logger()
	return logger
}

// TODO - Need to determine best approach to dynamic flattening
// Option 1 - Read second row in file, expand JSON blob and use that as the baseline for what keys are allowed - throw-out extraneous keys - faster but possible data-loss, good if keys are universal
// Option 2 - Iterate over entire file once, find all possible JSON keys and store in order - then for iterate over the file AGAIN and for each record we process, check for matching key-names and fill nils - slower but no data-loss.
func decodeJson(m map[string]interface{}) []string {
	values := make([]string, 0, len(m))
	for _, v := range m {
		switch vv := v.(type) {
		case map[string]interface{}:
			for _, value := range decodeJson(vv) {
				values = append(values, value)
			}
		case string:
			values = append(values, vv)
		case float64:
			values = append(values, strconv.FormatFloat(vv, 'f', -1, 64))
		case []interface{}:
			// Arrays aren't currently handled - this would include columns such as 'AffectedColumns'
			values = append(values, "ErrorArrayNotHandled")
		case bool:
			values = append(values, strconv.FormatBool(vv))
		case nil:
			values = append(values, "ErrorNil")
		default:
			values = append(values, "ErrorTypeNotHandled")
		}
	}
	return values
}

func decodeJsonKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	/*	for k, _ := range m {
		keys = append(keys, k)
	}*/
	for k, v := range m {
		switch vv := v.(type) {
		// Map is the only special one we need to consider since there will be additional embedded keys within
		case map[string]interface{}:
			for _, kk := range decodeJsonKeys(vv) {
				keys = append(keys, kk)
			}
		default:
			keys = append(keys, k)
		}
	}
	return keys
}

func openInput(inputFile string) (*os.File, error) {
	inputF, err := os.Open(inputFile)
	return inputF, err
}

func createOutput(outputFile string) (*os.File, error) {
	outputF, err := os.Create(outputFile)
	return outputF, err
}

func setupReadWrite(inputF *os.File, outputF *os.File) (*csv.Reader, *csv.Writer, error) {
	writer := csv.NewWriter(outputF)
	parser := csv.NewReader(inputF)
	parser.LazyQuotes = true
	return parser, writer, nil
}

func getNewPW(logger zerolog.Logger, inputFile string, outputFile string) (*csv.Reader, *csv.Writer, *os.File, *os.File, error) {
	inputF, err := openInput(inputFile)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	outputF, err := createOutput(outputFile)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	parser, writer, err := setupReadWrite(inputF, outputF)
	if err != nil {
		logger.Error().Msg(err.Error())
	}
	return parser, writer, inputF, outputF, err
}

func ExtractTarGz(gzipStream io.Reader, logger zerolog.Logger, dir string) error {
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	tarReader := tar.NewReader(uncompressedStream)
	for true {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error().Msg(err.Error())
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			targetDir := fmt.Sprintf("%v\\%v", dir, header.Name)
			err := os.MkdirAll(targetDir, 0755)
			if err != nil {
				if os.IsExist(err) {
				} else {
					logger.Error().Msgf("Error Extracting: %v", err.Error())
					return err
				}
			}
		case tar.TypeReg:
			targetDir := fmt.Sprintf("%v\\%v", dir, header.Name)
			outFile, err := os.Create(targetDir)
			if err != nil {
				logger.Error().Msg(err.Error())
				return err
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				logger.Error().Msg(err.Error())
				return err
			}
			outFile.Close()

		default:
			logger.Error().Msg(err.Error())
			return err
		}
	}
	return nil
}

func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func combineOutputs(arguments map[string]any, logger zerolog.Logger) error {
	logger.Info().Msg("Combining Outputs per Directory")
	logger.Info().Msg("Note: The first file in each directory will provide the headers for all subsequent files - those that have a mismatch will be logged and skipped.")
	fileDirMap := make(map[string][]string)

	err := filepath.WalkDir(arguments["outputdir"].(string), func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			fileDirMap[filepath.Dir(path)] = append(fileDirMap[filepath.Dir(path)], path)
		}
		return nil
	})
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}

	var MainWaiter sync.WaitGroup
	for k := range fileDirMap {
		if len(fileDirMap[k]) == 0 {
			continue
		}

		var waiter WaitGroupCount
		writeChannel := make(chan []string)
		t := time.Now().Format("20060102150405")
		tmpCombinedOutput := fmt.Sprintf("%v\\combinedOutput_%v.csv", k, t)
		outputF, err := createOutput(tmpCombinedOutput)
		if err != nil {
			logger.Error().Msg(err.Error())
			continue
		}
		headers, err := getCSVHeaders(fileDirMap[k][0])
		if err != nil {
			logger.Error().Msg(err.Error())
			continue
		}
		writer := csv.NewWriter(outputF)
		writer.Write(headers)
		// Now we have created an output CSV and written the headers from the first file to it - for each file we will kick off a gorroutine that will read and send records to the writer channel
		// Once all readers are done, the waitgroup will be done and the per-file channel will be closed
		// Once all per-file channels are closed, are independent writers will finish and signal that the main wait group is done and we can proceed with execution

		MainWaiter.Add(1)
		go combineWriterListen(outputF, writer, writeChannel, logger, &MainWaiter)
		for _, v := range fileDirMap[k] {
			waiter.Add(1)
			go readAndSendToChannel(v, writeChannel, &waiter, logger, headers)
		}
		go closeChannelWhenDone(writeChannel, &waiter)
	}
	logger.Info().Msg("Waiting...")
	MainWaiter.Wait()
	logger.Info().Msg("Done!")
	return nil
}

func combineWriterListen(outputF *os.File, writer *csv.Writer, c chan []string, logger zerolog.Logger, MainWaiter *sync.WaitGroup) {
	// Will receive a handle to a pre-setup CSV writer and listen on a channel for incoming records to write, breaking when the channel is closed.
	defer MainWaiter.Done()
	defer outputF.Close()
	for {
		record, ok := <-c
		if !ok {
			break
		} else {
			err := writer.Write(record)
			if err != nil {
				logger.Error().Msg(err.Error())
			}
		}
	}
	writer.Flush()
	err := writer.Error()
	if err != nil {
		logger.Error().Msg(err.Error())
	}

}

func regexFirstPublicIPFromString(input string) (string, bool) {
	// If we find more than 1 match, check for first non-private IP
	// If there is only one match, just return it
	match := ipv4_regex.FindAllStringSubmatch(input, -1)
	ipList := make([]string, 0)
	if match != nil {
		for _, v := range match {
			ipList = append(ipList, v[1])
		}
		// Iterate through IP matches - return the first non-private one - otherwise, just return the first one in the slice
		for _, v := range ipList {
			if !isPrivateIP(net.ParseIP(v), v) {
				return v, true
			}
		}
		return ipList[0], true
	}
	// TODO - Implement private net checks for IPv6
	match2 := ipv6_regex.FindAllStringSubmatch(input, -1)
	if match2 != nil {
		for _, v := range match2 {
			return v[1], true
		}
	}
	/*	if match != nil {
			for i, name := range ipv4_regex.SubexpNames() {
				if i != 0 && name != "" {

					return match[i], true
				}
			}
		}
		match2 := ipv6_regex.FindStringSubmatch(input)
		if match2 != nil {
			for i, _ := range ipv4_regex.SubexpNames() {
				return match2[i], true
			}
		}*/
	return "", false
}

func ReadFileToSlice(filename string, logger zerolog.Logger) []string {
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		logger.Error().Err(err)
		return make([]string, 0)
	}
	reader := bufio.NewReader(file)
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		lines = append(lines, strings.TrimSpace(line))
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error().Err(err)
			return make([]string, 0)
		}
	}
	return lines
	//reader := bufio.NewReader(file)
}

func findTargetIndexInSlice(headers []string, targetCol string) int {
	// Check a slice for a target string - if it exists, return the index, otherwise, -1
	for i, v := range headers {
		v := strings.ReplaceAll(v, "\"", "")
		if v == targetCol || strings.Contains(v, targetCol) {
			return i
		}
	}
	return -1
}

func closeChannelWhenDone(c chan []string, wg *WaitGroupCount) {
	// Waits on a WaitGroup to conclude and closes the associated channel when done - used to synchronize waitgroups sending to a channel
	wg.Wait()
	close(c)
}

func readAndSendToChannel(csvFile string, c chan []string, waiter *WaitGroupCount, logger zerolog.Logger, initialHeaders []string) {
	defer waiter.Done()
	inputHeaderFile, err := openInput(csvFile)
	if err != nil {
		logger.Error().Msg(err.Error())
		return
	}
	defer inputHeaderFile.Close()
	idx := 0
	reader := csv.NewReader(inputHeaderFile)
	for {
		record, Ferr := reader.Read()

		if Ferr == io.EOF {
			break
		}
		if Ferr != nil {
			logger.Error().Msgf("Error Reading Record in %v: %v", csvFile, Ferr.Error())
			continue
		}
		if idx == 0 {
			if !reflect.DeepEqual(initialHeaders, record) {
				logger.Error().Msgf("Header Mismatch - Skipping: %v", csvFile)
				return
			}
			idx += 1
			continue
		}
		c <- record
	}
}

func removeSpace(s string) string {
	rr := make([]rune, 0, len(s))
	for _, r := range s {
		if !unicode.IsSpace(r) {
			rr = append(rr, r)
		}
	}
	return string(rr)
}

func getDateBounds(tempArgs map[string]any) (time.Time, time.Time) {
	startDate, _ := time.Parse("2006-01-02", "1800-01-01")
	endDate, _ := time.Parse("2006-01-02", "2300-01-01")
	sd, sdexist := tempArgs["startdate"].(time.Time)
	ed, edexist := tempArgs["enddate"].(time.Time)
	if sdexist {
		startDate = sd
	}
	if edexist {
		endDate = ed
	}
	return startDate, endDate
}

func scannerFromFile(reader io.Reader) (*bufio.Scanner, error) {
	var scanner *bufio.Scanner
	bReader := bufio.NewReader(reader)
	testBytes, err := bReader.Peek(2)
	if err != nil {
		return nil, err
	}
	if testBytes[0] == 31 && testBytes[1] == 139 {
		gzipReader, err := gzip.NewReader(bReader)
		if err != nil {
			return nil, err
		}
		scanner = bufio.NewScanner(gzipReader)
	} else {
		scanner = bufio.NewScanner(bReader)
	}
	return scanner, nil
}

func copyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}
	return nil
}
