package network

import (
	"fmt"
	"net"
	"strings"

	"github.com/WarrDoge/tuncat/internal/engine/netutil"
)

func NormalizeDNSDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	normalized := make([]string, 0, len(domains))

	for _, domain := range domains {
		d := strings.ToLower(strings.TrimSpace(domain))
		d = strings.TrimPrefix(d, ".")
		if d == "" {
			continue
		}
		if _, exists := seen[d]; exists {
			continue
		}
		seen[d] = struct{}{}
		normalized = append(normalized, d)
	}

	return normalized
}

func isContiguousMask(mask net.IP) bool {
	ip4 := mask.To4()
	if ip4 == nil {
		return false
	}
	seenZero := false
	for _, b := range ip4 {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) != 0 {
				if seenZero {
					return false
				}
			} else {
				seenZero = true
			}
		}
	}
	return true
}

func routeToCIDR(route string) (string, error) {
	route = strings.TrimSpace(route)
	if route == "" {
		return "", fmt.Errorf("route entry is empty")
	}

	if _, _, err := net.ParseCIDR(route); err == nil {
		return route, nil
	}

	parts := strings.Split(route, "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid route %q", route)
	}
	maskIP := net.ParseIP(parts[1])
	if maskIP == nil {
		return "", fmt.Errorf("invalid route %q", route)
	}
	if !isContiguousMask(maskIP) {
		return "", fmt.Errorf("invalid route %q: netmask %s is non-contiguous", route, parts[1])
	}

	cidr := netutil.IpMaskToCIDR(route)
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return "", fmt.Errorf("invalid route %q", route)
	}
	return cidr, nil
}
