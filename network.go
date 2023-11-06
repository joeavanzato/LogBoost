package main

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

var privateIPBlocks []*net.IPNet

func setupPrivateNetworks() error {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
	return nil
}

func downloadFile(logger zerolog.Logger, url string, filepath string, key string) (err error) {
	if strings.HasPrefix(url, "https://download.maxmind.com") {
		logger.Info().Msgf("Downloading MaxMind %v DB to path: %v", key, filepath)
	} else {
		logger.Info().Msgf("Downloading File %v to path: %v", url, filepath)
	}
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
	// TODO It is possible to set custom resolvers here - should explore setting up a rotating resolver to spread requests between multiple nameservers
	// https://stackoverflow.com/questions/59889882/specifying-dns-server-for-lookup-in-go
	records, err := net.DefaultResolver.LookupAddr(context.Background(), ip)
	if err != nil {
		return []string{"None"}
	}
	return records
}

func isPrivateIP(ip net.IP, ipstring string) bool {
	// TODO There is also ip.IsPrivate() - does that supercede the need for these checks?
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	/*	if tenDot.Contains(ip) || sevenTwoDot.Contains(ip) || oneNineTwoDot.Contains(ip) || ipstring == "127.0.0.1" || ipstring == "::" || ipstring == "::1" || ipstring == "0.0.0.0" {
		return true
	}*/

	return false
}
