package helpers

import (
	"errors"
	"fmt"
	"github.com/joeavanzato/logboost/vars"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Ideas inspired from https://github.com/likexian/whois

var DefaultClient = NewClient()

type Client struct {
	dialer          proxy.Dialer
	timeout         time.Duration
	elapsed         time.Duration
	disableStats    bool
	disableReferral bool
}

func Whois(domain string, servers ...string) (result string, err error) {
	return DefaultClient.Whois(domain, servers...)
}

func NewClient() *Client {
	return &Client{
		dialer: &net.Dialer{
			Timeout: vars.WhoisTimeout,
		},
		timeout: vars.WhoisTimeout,
	}
}

func (c *Client) Whois(domain string, servers ...string) (result string, err error) {
	start := time.Now()
	defer func() {
		result = strings.TrimSpace(result)
		if result != "" && !c.disableStats {
			result = fmt.Sprintf("%s\n\n%% Query time: %d msec\n%% WHEN: %s\n",
				result, time.Since(start).Milliseconds(), start.Format("Mon Jan 02 15:04:05 MST 2006"),
			)
		}
	}()

	domain = strings.Trim(strings.TrimSpace(domain), ".")
	if domain == "" {
		return "", errors.New("whois: domain is empty")
	}

	isASN := IsASN(domain)
	if isASN {
		if !strings.HasPrefix(strings.ToUpper(domain), "AS") {
			domain = "AS" + domain
		}
	}

	if !strings.Contains(domain, ".") && !strings.Contains(domain, ":") && !isASN {
		return c.rawQuery(domain, vars.WhoisServers[0], vars.WhoisPort)
	}

	var server, port string
	if len(servers) > 0 && servers[0] != "" {
		server = strings.ToLower(servers[0])
		port = fmt.Sprint(vars.WhoisPort)
	} else {
		ext := getExtension(domain)
		result, err := c.rawQuery(ext, vars.WhoisServers[0], vars.WhoisPort)
		if err != nil {
			return "", fmt.Errorf("whois: query for whois server failed: %w", err)
		}
		server, port = getServer(result)
		if server == "" {
			return "", fmt.Errorf("%w: %s", errors.New("whois: no whois server found for domain"), domain)
		}
	}

	result, err = c.rawQuery(domain, server, port)
	if err != nil {
		return
	}

	if c.disableReferral {
		return
	}

	refServer, refPort := getServer(result)
	if refServer == "" || refServer == server {
		return
	}

	data, err := c.rawQuery(domain, refServer, refPort)
	if err == nil {
		result += data
	}

	return
}

func (c *Client) rawQuery(domain, server, port string) (string, error) {
	c.elapsed = 0
	start := time.Now()

	if server == "whois.arin.net" {
		if IsASN(domain) {
			domain = "a + " + domain
		} else {
			domain = "n + " + domain
		}
	}

	if server == "whois.godaddy" {
		server = "whois.godaddy.com"
	}
	if server == "porkbun.com/whois" {
		server = "whois.porkbun.com"
	}

	conn, err := c.dialer.Dial("tcp", net.JoinHostPort(server, port))
	if err != nil {
		return "", fmt.Errorf("whois: connect to whois server failed: %w", err)
	}

	defer conn.Close()
	c.elapsed = time.Since(start)

	_ = conn.SetWriteDeadline(time.Now().Add(c.timeout - c.elapsed))
	_, err = conn.Write([]byte(domain + "\r\n"))
	if err != nil {
		return "", fmt.Errorf("whois: send to whois server failed: %w", err)
	}

	c.elapsed = time.Since(start)

	_ = conn.SetReadDeadline(time.Now().Add(c.timeout - c.elapsed))
	buffer, err := io.ReadAll(conn)
	if err != nil {
		return "", fmt.Errorf("whois: read from whois server failed: %w", err)
	}

	c.elapsed = time.Since(start)

	return string(buffer), nil
}

func getExtension(domain string) string {
	ext := domain

	if net.ParseIP(domain) == nil {
		domains := strings.Split(domain, ".")
		ext = domains[len(domains)-1]
	}

	if strings.Contains(ext, "/") {
		ext = strings.Split(ext, "/")[0]
	}

	return ext
}

func getServer(data string) (string, string) {
	tokens := []string{
		"Registrar WHOIS Server: ",
		"whois: ",
		"ReferralServer: ",
		"refer: ",
	}

	for _, token := range tokens {
		start := strings.Index(data, token)
		if start != -1 {
			start += len(token)
			end := strings.Index(data[start:], "\n")
			server := strings.TrimSpace(data[start : start+end])
			server = strings.TrimPrefix(server, "http:")
			server = strings.TrimPrefix(server, "https:")
			server = strings.TrimPrefix(server, "whois:")
			server = strings.TrimPrefix(server, "rwhois:")
			server = strings.Trim(server, "/")
			port := vars.WhoisPort
			if strings.Contains(server, ":") {
				v := strings.Split(server, ":")
				server, port = v[0], v[1]
			}
			return server, port
		}
	}

	return "", ""
}

func IsASN(s string) bool {
	s = strings.ToUpper(s)

	s = strings.TrimPrefix(s, "AS")
	_, err := strconv.Atoi(s)

	return err == nil
}
