package helpers

import (
	"errors"
	"fmt"
	"github.com/joeavanzato/logboost/vars"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"strings"
)

func FindOrGetDBs(arguments map[string]any, logger zerolog.Logger) error {
	dir, err := os.Getwd()
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}
	if arguments["dbdir"].(string) != "" {
		dir = arguments["dbdir"].(string)
	}

	logger.Info().Msgf("Checking Directory '%v' for MaxMind DBs", dir)
	globPattern := fmt.Sprintf("%v\\Geo*.mmdb", dir)
	entries, err := filepath.Glob(globPattern)
	if err != nil {
		logger.Error().Msg(err.Error())
		return err
	}

	for _, e := range entries {
		if strings.HasSuffix(e, vars.MaxMindFiles["ASN"]) {
			vars.MaxMindStatus["ASN"] = true
			vars.MaxMindFileLocations["ASN"] = e
		} else if strings.HasSuffix(e, vars.MaxMindFiles["City"]) {
			vars.MaxMindStatus["City"] = true
			vars.MaxMindFileLocations["City"] = e
		} else if strings.HasSuffix(e, vars.MaxMindFiles["Country"]) {
			vars.MaxMindStatus["Country"] = true
			vars.MaxMindFileLocations["Country"] = e
		} else if strings.HasSuffix(e, vars.MaxMindFiles["Domain"]) {
			vars.MaxMindStatus["Domain"] = true
			vars.MaxMindFileLocations["Domain"] = e
		}
	}

	for k, v := range vars.MaxMindStatus {
		if v == true {
			logger.Info().Msgf("Found Existing %v DB file at: %v", k, vars.MaxMindFileLocations[k])
			if arguments["updategeo"].(bool) {
				if k == "Domain" {
					logger.Info().Msg("Skipping Domain DB Update")
					continue
				}
				logger.Info().Msgf("Updating Local MaxMind %v DB", k)
				err = updateMaxMind(logger, dir, k)
				if err != nil {
					return err
				}
			}
		} else {
			logger.Info().Msgf("Could not find %v DB at %v\\%v, downloading!", k, dir, vars.MaxMindFiles[k])
			if k == "Domain" {
				logger.Info().Msg("Skipping Domain DB Update")
				continue
			}
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
	err := DownloadFile(logger, vars.MaxMindURLs[k], gzFile, k)
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
	err = CopyFile(file[0], destFile)
	if err != nil {
		vars.MaxMindFileLocations[k] = file[0]
	} else {
		vars.MaxMindFileLocations[k] = destFile
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

func SetAPIUrls(arguments map[string]any, logger zerolog.Logger) error {
	apiKey := ""
	if arguments["api"].(string) == "" {
		logger.Info().Msg("API Key not provided at command line - checking for ENV VAR 'MM_API'")
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
			apiKey = FileToSlice("mm_api.txt", logger)[0]
		}
	} else {
		logger.Info().Msgf("Reading API Key from provided commandline")
		apiKey = arguments["api"].(string)
	}
	if apiKey == "" {
		logger.Error().Msg("Could not find valid MaxMind API Key")
		return errors.New("Could not find valid MaxMind API Key")
	}
	vars.GeoLiteASNDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=%v&suffix=tar.gz", apiKey)
	vars.GeoLiteCityDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%v&suffix=tar.gz", apiKey)
	vars.GeoLiteCountryDBURL = fmt.Sprintf("https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%v&suffix=tar.gz", apiKey)

	vars.MaxMindURLs["ASN"] = vars.GeoLiteASNDBURL
	vars.MaxMindURLs["City"] = vars.GeoLiteCityDBURL
	vars.MaxMindURLs["Country"] = vars.GeoLiteCountryDBURL
	return nil
}
