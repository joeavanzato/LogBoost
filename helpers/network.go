package helpers

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var PrivateIPBlocks []*net.IPNet

var resolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Millisecond * time.Duration(10000),
		}
		return d.DialContext(ctx, network, "1.1.1.1:53")
	},
}

func SetupPrivateNetworks() error {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"192.0.0.0/24",   // RFC 5735
		"192.0.2.0/24",   // RFC 5737
		"169.254.0.0/16", // RFC3927 link-local
		"224.0.0.0/4",    // RFC 3171
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // Private Internets
		//"Fd00::/7",
		"64:ff9b:1::/48", // Private Internets
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		PrivateIPBlocks = append(PrivateIPBlocks, block)
	}
	return nil
}

func DownloadFile(logger zerolog.Logger, url string, filepath string, key string) (err error) {
	// TODO - Refactor to handle unit testing
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
		return fmt.Errorf("HTTP Status Error: %s", resp.Status)
	}
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	logger.Info().Msgf("Successfully Downloaded: %v", url)
	return nil
}

func DownloadAuthenticatedFile(logger zerolog.Logger, url string, filepath string, key string, user string, password string) (err error) {
	// TODO - Refactor to handle unit testing
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
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(user, password)
	//resp, err := http.Get(url)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP Status Error: %s", resp.Status)
	}
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}
	logger.Info().Msgf("Successfully Downloaded: %v", url)
	return nil
}

func LookupIPRecords(ip string) []string {
	// TODO It is possible to set custom resolvers here - should explore setting up a rotating resolver to spread requests between multiple nameservers
	// https://stackoverflow.com/questions/59889882/specifying-dns-server-for-lookup-in-go
	records, err := net.DefaultResolver.LookupAddr(context.Background(), ip)
	if err != nil {
		return []string{"None"}
	}
	return records
}

func IsPrivateIP(ip net.IP, ipstring string) bool {
	// TODO There is also ip.IsPrivate() - does that supercede the need for these checks?
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, block := range PrivateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	if ip.IsPrivate() {
		return true
	}
	if ipstring == "127.0.0.1" || ipstring == "::" || ipstring == "::1" || ipstring == "0.0.0.0" || strings.HasPrefix(ipstring, "255.") {
		return true
	}

	return false
}
