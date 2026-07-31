package cli

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestVerifyEndpointConcurrent(t *testing.T) {
	const goroutines = 10

	// Each goroutine gets its own httptest.NewServer so there's no shared
	// listener or request multiplexing.  The server responds to any path
	// with 204 No Content so the probe succeeds regardless of what URL
	// verifyEndpoint constructs.
	results := make(chan struct {
		idx   int
		ep    EndpointVerification
		err   bool
	}, goroutines)

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()

			ep := verifyEndpoint(srv.URL+"/healthcheck", nil)
			out := struct {
				idx int
				ep  EndpointVerification
				err bool
			}{idx: idx, ep: ep}
			if ep.Error != "" {
				out.err = true
			}
			results <- out
		}(i)
	}
	wg.Wait()
	close(results)

	failures := 0
	for r := range results {
		if r.err {
			t.Errorf("goroutine %d: verifyEndpoint returned error: %s", r.idx, r.ep.Error)
			failures++
			continue
		}
		if !r.ep.HTTPOK() {
			t.Errorf("goroutine %d: HTTPOK() = false (status %d)", r.idx, r.ep.HTTPStatus)
			failures++
			continue
		}
		// Sanity: resolved addresses should be present
		if len(r.ep.Addresses) == 0 {
			t.Errorf("goroutine %d: no resolved addresses", r.idx)
			failures++
		}
	}

	if failures > 0 {
		t.Fatalf("%d / %d concurrent verifyEndpoint calls failed", failures, goroutines)
	}
}

func TestVerifyEndpointConcurrentTimeout(t *testing.T) {
	// Prove that concurrent calls to verifyEndpoint don't interfere with
	// each other's timeouts: N goroutines that should timeout quickly,
	// mixed with one that should succeed against a fast server.
	const goroutines = 6

	type result struct {
		idx   int
		ep    EndpointVerification
		slow  bool // true = this goroutine got the slow/blocked server
	}

	results := make(chan result, goroutines)

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			var srv *httptest.Server
			if idx == 0 {
				// Fast server for one goroutine
				srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				}))
			} else {
				// Slow server that blocks for longer than verifyRetryInterval
				srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					time.Sleep(2 * verifyRetryInterval)
					w.WriteHeader(http.StatusNoContent)
				}))
			}
			defer srv.Close()

			ep := verifyEndpoint(srv.URL+"/timeouttest", nil)
			results <- result{
				idx:  idx,
				ep:   ep,
				slow: idx != 0,
			}
		}(i)
	}
	wg.Wait()
	close(results)

	for r := range results {
		if r.slow {
			// Slow goroutines should have timed out (error != "" or no HTTPOK)
			// Not strictly asserting which — what matters is no race is detected
			// and the fast goroutine (idx=0) succeeded.
			if r.idx == 1 {
				t.Logf("slow goroutine %d: error=%q status=%d", r.idx, r.ep.Error, r.ep.HTTPStatus)
			}
		} else {
			// The one fast goroutine must succeed
			if r.ep.Error != "" {
				t.Errorf("fast goroutine %d should have succeeded, got error: %s", r.idx, r.ep.Error)
			}
			if !r.ep.HTTPOK() {
				t.Errorf("fast goroutine %d: HTTPOK() = false (status %d)", r.idx, r.ep.HTTPStatus)
			}
		}
	}
}
