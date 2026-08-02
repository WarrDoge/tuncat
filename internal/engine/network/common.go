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

	mask := net.ParseIP(parts[1])
	if mask == nil {
		return "", fmt.Errorf("invalid route %q", route)
	}

	// Reject non-contiguous netmasks (e.g. 255.0.0.255) that would
	// produce a wrong prefix length via net.IPMask.Size().
	// Size() returns (0, 0) for non-contiguous masks and (0, 32) for 0.0.0.0.
	if ones, bits := net.IPMask(mask.To4()).Size(); ones == 0 && bits == 0 {
		return "", fmt.Errorf("non-contiguous netmask in route %q", route)
	}

	cidr := netutil.IpMaskToCIDR(route)
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return "", fmt.Errorf("invalid route %q", route)
	}
	return cidr, nil
}
