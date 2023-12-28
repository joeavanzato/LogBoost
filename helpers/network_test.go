package helpers

import (
	"net"
	"testing"
)

//var AferoTestingFS = afero.NewOsFs()

func TestSetupPrivateNetworks(t *testing.T) {
	want := 12
	err := SetupPrivateNetworks()
	if err != nil {
		t.Fatalf(`Error setupPrivateNetworks: %v`, err)
	}
	if len(PrivateIPBlocks) != want {
		t.Fatalf(`Error setupPrivateNetworks - wanted %v, got %v`, want, len(PrivateIPBlocks))
	}
}

func TestIsPrivateIP(t *testing.T) {
	// TODO - Add more IPv4/IPv6 tests to each
	privateIPs := []string{"127.0.0.1", "192.168.3.5", "172.16.2.3", "255.255.255.255", "fe80::ffff:ffff:ffff:ffff", "::1", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "64:ff9b:1:ffff:ffff:ffff:ffff:ffcf"}
	for _, v := range privateIPs {
		if !IsPrivateIP(net.ParseIP(v), v) {
			t.Fatalf(`Error isPrivateIP: wanted true, got false for value: %v`, v)
		}
	}
	publicIPs := []string{"8.8.8.8", "32.3.54.1", "1.1.1.1", "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffcf", "2001::ffff:ffff:ffff:ffff:ffff:fcff"}
	for _, v := range publicIPs {
		if IsPrivateIP(net.ParseIP(v), v) {
			t.Fatalf(`Error isPrivateIP: wanted false, got true for value: %v`, v)
		}
	}
}

func TestLookupIP(t *testing.T) {
	results := LookupIPRecords("8.8.8.8")
	if len(results) != 1 {
		t.Fatalf(`Error lookupIPRecords - wanted 1, got %v`, len(results))
	}
	newresults := LookupIPRecords("non-existent")
	if len(newresults) != 1 {
		t.Fatalf(`Error lookupIPRecords - wanted 0, got %v`, len(newresults))
	}
	if newresults[0] != "None" {
		t.Fatalf(`Error lookupIPRecords - wanted None, got %v`, newresults[0])
	}
}

// TODO - Refactor downloadFile to betterr support testing
