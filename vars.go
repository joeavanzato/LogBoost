package main

import (
	"net"
	"regexp"
	"sync"
)

const logFile = "log2geo.log"

var extraKeysColumnName = "EXTRA_KEYS"

var auditLogIPRegex = regexp.MustCompile(`.*ClientIP":"(?P<ClientIP>.*?)",.*`)

var geoLiteASNDBURL = ""
var geoLiteCityDBURL = ""
var geoLiteCountryDBURL = ""

var maxMindFiles = map[string]string{
	"ASN":     "GeoLite2-ASN.mmdb",
	"City":    "GeoLite2-City.mmdb",
	"Country": "GeoLite2-Country.mmdb",
}

var maxMindURLs = map[string]string{
	"ASN":     geoLiteASNDBURL,
	"City":    geoLiteCityDBURL,
	"Country": geoLiteCountryDBURL,
}

var maxMindStatus = map[string]bool{
	"ASN":     false,
	"City":    false,
	"Country": false,
}

var maxMindFileLocations = map[string]string{
	"ASN":     "",
	"City":    "",
	"Country": "",
}

// Used in func visit to add log paths as we crawl the input directory
var logsToProcess = make([]string, 0)

var geoFields = []string{"l2g_IP", "l2g_ASN", "l2g_Country", "l2g_City", "l2g_Domains", "l2g_ThreatCategory"}

var ipv6_regex = regexp.MustCompile(`.*(?P<ip>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))).*`)

// var ipv4_regex = regexp.MustCompile(`.*(?P<ip>((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}).*`)
var ipv4_regex = regexp.MustCompile(`.*?(?P<ip>\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b).*?`)
var tenDot = net.IPNet{
	IP:   net.ParseIP("10.0.0.0"),
	Mask: net.CIDRMask(8, 32),
}
var sevenTwoDot = net.IPNet{
	IP:   net.ParseIP("172.16.0.0"),
	Mask: net.CIDRMask(12, 32),
}
var oneNineTwoDot = net.IPNet{
	IP:   net.ParseIP("192.168.0.0"),
	Mask: net.CIDRMask(16, 32),
}

// Controls whether we collect files in visit() beyond .log, .csv and .txt - set by -getall param
var getAllFiles = false

// This set of args is now deprecated since we are pulling down tor nodes/exit nodes as part of the -buildti, -updateti, -useti sequence of arguments
var torExitNodeURL = "https://www.dan.me.uk/torlist/?exit"
var torExitNodeFile = "tor_exit_nodes.txt"
var torNodeMap = make(map[string]struct{})
var doTorEnrich = false
var torCheckMut = sync.RWMutex{}
