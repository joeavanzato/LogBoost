package main

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"net"
	"net/http"
	"os"
)

func downloadFile(logger zerolog.Logger, url string, filepath string, key string) (err error) {
	logger.Info().Msgf("Downloading File %v to path: %v", url, filepath)
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	return nil
}

func lookupIPRecords(ip string) []string {
	records, err := net.DefaultResolver.LookupAddr(context.Background(), ip)
	if err != nil {
		return []string{"None"}
	}
	return records
}

func isPrivateIP(ip net.IP, ipstring string) bool {
	// TODO - Implement private net checks for IPv6
	if tenDot.Contains(ip) || sevenTwoDot.Contains(ip) || oneNineTwoDot.Contains(ip) || ipstring == "127.0.0.1" || ipstring == "::" || ipstring == "::1" || ipstring == "0.0.0.0" {
		return true
	}

	return false
}
