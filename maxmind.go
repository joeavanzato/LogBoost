package main

import (
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"strings"
)

func findOrGetDBs(arguments map[string]any, logger zerolog.Logger) error {
	dir, err := os.Getwd()
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	if arguments["dbdir"].(string) != "" {
		dir = arguments["dbdir"].(string)
	}

	logger.Info().Msgf("Checking Directory '%v' for MaxMind DBs", dir)
	globPattern := fmt.Sprintf("%v\\GeoLite2-*.mmdb", dir)
	entries, err := filepath.Glob(globPattern)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}

	for _, e := range entries {
		if strings.HasSuffix(e, maxMindFiles["ASN"]) {
			maxMindStatus["ASN"] = true
			maxMindFileLocations["ASN"] = e
		} else if strings.HasSuffix(e, maxMindFiles["City"]) {
			maxMindStatus["City"] = true
			maxMindFileLocations["City"] = e
		} else if strings.HasSuffix(e, maxMindFiles["Country"]) {
			maxMindStatus["Country"] = true
			maxMindFileLocations["Country"] = e
		}
	}

	for k, v := range maxMindStatus {
		if v == true {
			logger.Info().Msgf("Found Existing %v DB file at: %v", k, maxMindFileLocations[k])
			if arguments["updategeo"].(bool) {
				logger.Info().Msgf("Updating Local MaxMind %v DB", k)
				err = updateMaxMind(logger, dir, k)
				if err != nil {
					return err
				}
			}
		} else {
			logger.Info().Msgf("Could not find %v DB at %v\\%v, downloading!", k, dir, maxMindFiles[k])
			err = updateMaxMind(logger, dir, k)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func updateMaxMind(logger zerolog.Logger, dir string, k string) error {
	gzFile := fmt.Sprintf("%v\\%v.tar.gz", dir, k)
	// Download It First
	// TODO - Uncomment when done testing
	err := downloadFile(logger, maxMindURLs[k], gzFile, k)
	if err != nil {
		logger.Error().Msg("Problem Downloading File!")
		logger.Error().Msg(err.Error())
		return err
	}
	// If successful, extract
	r, err := os.Open(gzFile)
	if err != nil {
		logger.Error().Msg(err.Error())
		r.Close()
		return err
	}
	err = ExtractTarGz(r, logger, dir)
	if err != nil {
		logger.Error().Msg(err.Error())
		r.Close()
		return err
	}
	r.Close()
	// Once we extract, we need to find the actual mmdb file which will be located within a newly created directory of the naming format GeoLite2-KEY_*
	globPattern := fmt.Sprintf("%v\\GeoLite2-%v_*\\GeoLite2-%v.mmdb", dir, k, k)
	file, err := filepath.Glob(globPattern)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	// Copy desired file out to main dir
	destFile := fmt.Sprintf("GeoLite2-%v.mmdb", k)
	err = copyFile(file[0], destFile)
	if err != nil {
		maxMindFileLocations[k] = file[0]
	} else {
		maxMindFileLocations[k] = destFile
	}

	// Remove downloaded gz
	err = os.Remove(gzFile)
	if err != nil {
		logger.Error().Msgf("Error Removing Temp Zip: %v", err.Error())
	}

	tempDirPattern := fmt.Sprintf("%v\\GeoLite2-%v_*", dir, k)
	dirlist, err := filepath.Glob(tempDirPattern)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	// Remove extracted GZ since we have copied file out now to $KEY.mmdb
	err = os.RemoveAll(dirlist[0])
	if err != nil {
		logger.Error().Msgf("Error Removing Temp Dir: %v", err.Error())
	}
	return nil
}

func setAPIUrls(arguments map[string]any, logger zerolog.Logger) error {
	apiKey := ""
	if arguments["api"].(string) == "" {
		logger.Info().Msg("API Key not provided at command line - checking for ENV VAR")
		// API not provided at cmdline
		val, exists := os.LookupEnv("MM_API")
		if exists {
			apiKey = val
			logger.Info().Msg("Environment Variable MM_API Found")
		} else {
			logger.Info().Msg("Environment Variable MM_API Not Found, checking for mm_api.txt")
			_, err := os.Stat("mm_api.txt")
			if os.IsNotExist(err) {
				logger.Error().Msgf("Could not find mm_api.txt - downloads not possible.")
			}
			logger.Info().Msgf("Found mm_api.txt")
			apiKey = ReadFileToSlice("mm_api.txt", logger)[0]
		}
	} else {
		logger.Info().Msgf("Reading API Key from provided commandline")
		apiKey = arguments["api"].(string)
	}
	if apiKey == "" {
		logger.Error().Msg("Could not find valid MaxMind API Key")
		return errors.New("Could not find valid MaxMind API Key")
	}
	geoLiteASNDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=%v&suffix=tar.gz", apiKey)
	geoLiteCityDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%v&suffix=tar.gz", apiKey)
	geoLiteCountryDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%v&suffix=tar.gz", apiKey)

	maxMindURLs["ASN"] = geoLiteASNDBURL
	maxMindURLs["City"] = geoLiteCityDBURL
	maxMindURLs["Country"] = geoLiteCountryDBURL
	return nil
}
