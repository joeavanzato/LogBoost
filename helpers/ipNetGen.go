package helpers

import (
	"math/big"
	"net"
)

// https://github.com/korylprince/ipnetgen/blob/master/ipnetgen.go

// Increment increments the given net.IP by one bit. Incrementing the last IP in an IP space (IPv4, IPV6) is undefined.
func Increment(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		//only add to the next byte if we overflowed
		if ip[i] != 0 {
			break
		}
	}
}

// IPNetGenerator is a net.IPnet wrapper that you can iterate over
type IPNetGenerator struct {
	*net.IPNet
	count *big.Int

	//state
	idx     *big.Int
	current net.IP
}

// NewIPNetGenerator creates a new IPNetGenerator from a CIDR string, or an error if the CIDR is invalid.
func NewIPNetGenerator(cidr string) (*IPNetGenerator, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return NewFromIPNet(ipNet), nil
}

// NewFromIPNet creates a new IPNetGenerator from a *net.IPNet
func NewFromIPNet(ipNet *net.IPNet) *IPNetGenerator {
	ones, bits := ipNet.Mask.Size()

	newIP := make(net.IP, len(ipNet.IP))
	copy(newIP, ipNet.IP)

	count := big.NewInt(0)
	count.Exp(big.NewInt(2), big.NewInt(int64(bits-ones)), nil)

	return &IPNetGenerator{
		IPNet:   ipNet,
		count:   count,
		idx:     big.NewInt(0),
		current: newIP,
	}
}

// Next returns the next net.IP in the subnet
func (g *IPNetGenerator) Next() net.IP {
	g.idx.Add(g.idx, big.NewInt(1))
	if g.idx.Cmp(g.count) == 1 {
		return nil
	}
	current := make(net.IP, len(g.current))
	copy(current, g.current)
	Increment(g.current)

	return current
}
