package vars

import (
	"github.com/VictoriaMetrics/fastcache"
	"net"
	"regexp"
)

const LogFile = "logboost.log"

var ExtraKeysColumnName = "EXTRA_KEYS"

var AuditLogIPRegex = regexp.MustCompile(`.*ClientIP":"(?P<ClientIP>.*?)",.*`)

var GeoLiteASNDBURL = ""
var GeoLiteCityDBURL = ""
var GeoLiteCountryDBURL = ""

var MaxMindFiles = map[string]string{
	"ASN":     "GeoLite2-ASN.mmdb",
	"City":    "GeoLite2-City.mmdb",
	"Country": "GeoLite2-Country.mmdb",
	"Domain":  "GeoIP2-Domain.mmdb",
}

var MaxMindURLs = map[string]string{
	"ASN":     GeoLiteASNDBURL,
	"City":    GeoLiteCityDBURL,
	"Country": GeoLiteCountryDBURL,
	"Domain":  "",
}

var MaxMindStatus = map[string]bool{
	"ASN":     false,
	"City":    false,
	"Country": false,
	"Domain":  false,
}

var MaxMindFileLocations = map[string]string{
	"ASN":     "",
	"City":    "",
	"Country": "",
	"Domain":  "",
}

// Used in func visit to add log paths as we crawl the input directory
var LogsToProcess = make([]string, 0)

var GeoFields = []string{"lb_IP", "lb_ASN", "lb_Country", "lb_City", "lb_Domains", "lb_ThreatCategory", "lb_TLD"}

var Ipv6_regex = regexp.MustCompile(`.*(?P<ip>(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))).*`)

// var Ipv4_regex = regexp.MustCompile(`.*(?P<ip>((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}).*`)
var Ipv4_regex = regexp.MustCompile(`.*?(?P<ip>\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b).*?`)
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
var GetAllFiles = false

var DnsCacheFile = "dns.cache"

// 1 GB max cache size
var Dnsfastcache = fastcache.LoadFromFileOrNew(DnsCacheFile, 1_000_000_000)
