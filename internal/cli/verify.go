package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	verifyTimeout       = 10 * time.Second
	verifyRetryInterval = 500 * time.Millisecond
)

type EndpointVerification struct {
	Host       string
	DNSServers []string
	Addresses  []string
	Resolved   bool
	HTTPStatus int
	Attempts   int
	Error      string
	Duration   time.Duration
}

func (v EndpointVerification) HTTPOK() bool {
	return v.HTTPStatus >= 200 && v.HTTPStatus <= 399
}

func verifyEndpoint(urlStr string, dnsServers []string) EndpointVerification {
	start := time.Now()

	uri, err := url.Parse(strings.TrimSpace(urlStr))
	if err != nil {
		return EndpointVerification{Error: fmt.Sprintf("invalid verify_url: %v", err)}
	}
	if uri.Scheme != "http" && uri.Scheme != "https" {
		return EndpointVerification{Error: fmt.Sprintf("unsupported verify_url scheme %q", uri.Scheme)}
	}
	host := uri.Hostname()
	if host == "" {
		return EndpointVerification{Error: "verify_url host is empty"}
	}

	servers := normalizeDNSServers(dnsServers)
	result := EndpointVerification{
		Host:       host,
		DNSServers: append([]string(nil), servers...),
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: host},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   verifyRetryInterval,
		Transport: transport,
	}

	deadline := time.Now().Add(verifyTimeout)
	for {
		result.Attempts++
		addresses, resolveErr := resolveHost(host, servers)
		if resolveErr == nil {
			result.Addresses = addresses
			result.Resolved = true

			status, httpErr := probeHTTP(client, uri, host, addresses[0])
			result.HTTPStatus = status
			if httpErr == nil {
				result.Error = ""
				result.Duration = time.Since(start)
				return result
			}
			result.Error = fmt.Sprintf("HTTP probe failed: %v", httpErr)
		} else {
			result.Error = fmt.Sprintf("DNS lookup failed: %v", resolveErr)
		}

		if time.Now().Add(verifyRetryInterval).After(deadline) {
			result.Duration = time.Since(start)
			return result
		}
		time.Sleep(verifyRetryInterval)
	}
}

func normalizeDNSServers(dnsServers []string) []string {
	normalized := make([]string, 0, len(dnsServers))
	seen := map[string]struct{}{}
	for _, server := range dnsServers {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if net.ParseIP(server) == nil {
			continue
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		normalized = append(normalized, server)
	}
	return normalized
}

func resolveHost(host string, dnsServers []string) ([]string, error) {
	if len(dnsServers) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), verifyRetryInterval)
		defer cancel()
		return net.DefaultResolver.LookupHost(ctx, host)
	}

	var lastErr error
	for _, server := range dnsServers {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				dialer := &net.Dialer{Timeout: verifyRetryInterval}
				return dialer.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), verifyRetryInterval)
		addresses, err := resolver.LookupHost(ctx, host)
		cancel()
		if err == nil {
			return addresses, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no DNS servers available")
	}
	return nil, lastErr
}

func probeHTTP(client *http.Client, uri *url.URL, host, address string) (int, error) {
	target := *uri
	target.Host = net.JoinHostPort(address, portForURI(uri))

	req, err := http.NewRequest(http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, fmt.Errorf("build HTTP request failed: %w", err)
	}
	req.Host = host
	req.Header.Set("User-Agent", "tuncat")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

func portForURI(uri *url.URL) string {
	if port := uri.Port(); port != "" {
		return port
	}
	if strings.EqualFold(uri.Scheme, "https") {
		return strconv.Itoa(443)
	}
	return strconv.Itoa(80)
}
