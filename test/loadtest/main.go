// Command loadtest is a system-level load test for the identree API.
// It creates challenges and polls them across multiple concurrent workers,
// collecting latency histograms, throughput, and error counts.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	op       string // "create", "poll", "approve"
	duration time.Duration
	status   int
	err      error
}

type stats struct {
	mu       sync.Mutex
	results  []result
	errors   int64
	total    int64
	byOp     map[string][]time.Duration
	byStatus map[int]int64
}

func newStats() *stats {
	return &stats{
		byOp:     make(map[string][]time.Duration),
		byStatus: make(map[int]int64),
	}
}

func (s *stats) record(r result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, r)
	s.total++
	s.byOp[r.op] = append(s.byOp[r.op], r.duration)
	s.byStatus[r.status]++
	if r.err != nil || r.status >= 400 {
		s.errors++
	}
}

func (s *stats) report(elapsed time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("LOAD TEST RESULTS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total requests:  %d\n", s.total)
	fmt.Printf("Total errors:    %d (%.1f%%)\n", s.errors, float64(s.errors)/float64(max64(s.total, 1))*100)
	fmt.Printf("Total duration:  %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Throughput:      %.1f req/s\n", float64(s.total)/elapsed.Seconds())
	fmt.Println()

	// Per-operation breakdown
	for _, op := range []string{"create", "poll", "approve"} {
		durations := s.byOp[op]
		if len(durations) == 0 {
			continue
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		fmt.Printf("--- %s (%d requests) ---\n", op, len(durations))
		fmt.Printf("  min:    %s\n", durations[0].Round(time.Microsecond))
		fmt.Printf("  p50:    %s\n", percentile(durations, 50).Round(time.Microsecond))
		fmt.Printf("  p95:    %s\n", percentile(durations, 95).Round(time.Microsecond))
		fmt.Printf("  p99:    %s\n", percentile(durations, 99).Round(time.Microsecond))
		fmt.Printf("  max:    %s\n", durations[len(durations)-1].Round(time.Microsecond))
		fmt.Printf("  avg:    %s\n", avg(durations).Round(time.Microsecond))
		fmt.Println()
	}

	// Status code breakdown
	fmt.Println("--- HTTP status codes ---")
	for code, count := range s.byStatus {
		fmt.Printf("  %d: %d\n", code, count)
	}
	fmt.Println(strings.Repeat("=", 70))
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func avg(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	return total / time.Duration(len(durations))
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

type challengeResponse struct {
	ID       string `json:"challenge_id"`
	UserCode string `json:"user_code"`
}

func createChallenge(client *http.Client, baseURL, secret, username, hostname string) (challengeResponse, result) {
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"hostname": hostname,
	})

	start := time.Now()
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Shared-Secret", secret)

	resp, err := client.Do(req)
	dur := time.Since(start)
	if err != nil {
		return challengeResponse{}, result{op: "create", duration: dur, err: err}
	}
	defer resp.Body.Close()

	var cr challengeResponse
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		json.Unmarshal(respBody, &cr)
	}
	return cr, result{op: "create", duration: dur, status: resp.StatusCode}
}

func pollChallenge(client *http.Client, baseURL, secret, challengeID, hostname string) result {
	start := time.Now()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/challenge/"+challengeID+"?hostname="+hostname, nil)
	req.Header.Set("X-Shared-Secret", secret)

	resp, err := client.Do(req)
	dur := time.Since(start)
	if err != nil {
		return result{op: "poll", duration: dur, err: err}
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	return result{op: "poll", duration: dur, status: resp.StatusCode}
}

func main() {
	var (
		workers  = flag.Int("workers", 10, "number of concurrent workers")
		requests = flag.Int("requests", 100, "total number of challenge create+poll cycles per worker")
		duration = flag.Duration("duration", 0, "maximum test duration (0 = unlimited, run all requests)")
		baseURL  = flag.String("url", "http://localhost:8090", "identree server URL")
		secret   = flag.String("secret", "test-shared-secret-1234567890abc", "shared secret")
		mode     = flag.String("mode", "mixed", "test mode: create|poll|mixed")
	)
	flag.Parse()

	fmt.Printf("Load test: %d workers x %d requests, mode=%s, url=%s\n", *workers, *requests, *mode, *baseURL)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: *workers,
			MaxConnsPerHost:     *workers * 2,
		},
	}

	st := newStats()
	var wg sync.WaitGroup
	var stopped atomic.Bool

	// If duration is set, create a timer to stop workers
	if *duration > 0 {
		go func() {
			time.Sleep(*duration)
			stopped.Store(true)
		}()
	}

	startTime := time.Now()

	for w := range *workers {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for i := range *requests {
				if stopped.Load() {
					return
				}

				hostname := fmt.Sprintf("host-%d-%d", workerID, i)

				// Use unique username per request to avoid per-user pending
			// challenge rate limits (max 10 pending per user).
			uniqueUser := fmt.Sprintf("user-%d-%d", workerID, i)

			switch *mode {
			case "create":
				// Pure challenge creation throughput
				_, r := createChallenge(client, *baseURL, *secret, uniqueUser, hostname)
				st.record(r)

			case "poll":
				// Create then poll 10 times
				cr, r := createChallenge(client, *baseURL, *secret, uniqueUser, hostname)
				st.record(r)
				if cr.ID != "" {
					for range 10 {
						if stopped.Load() {
							return
						}
						pr := pollChallenge(client, *baseURL, *secret, cr.ID, hostname)
						st.record(pr)
					}
				}

			case "mixed":
				// Simulate real traffic: create, poll a few times
				cr, r := createChallenge(client, *baseURL, *secret, uniqueUser, hostname)
				st.record(r)
				if cr.ID != "" {
					// Poll 3 times (simulating PAM client waiting)
					for range 3 {
						if stopped.Load() {
							return
						}
						pr := pollChallenge(client, *baseURL, *secret, cr.ID, hostname)
						st.record(pr)
					}
				}
			}
			}
		}(w)
	}

	wg.Wait()
	elapsed := time.Since(startTime)

	// Fetch metrics if available
	fmt.Println("\n--- Server metrics snapshot ---")
	metricsResp, err := http.Get(*baseURL + "/metrics")
	if err == nil {
		defer metricsResp.Body.Close()
		body, _ := io.ReadAll(metricsResp.Body)
		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "identree_") && !strings.HasPrefix(line, "#") {
				fmt.Println("  " + line)
			}
		}
	} else {
		fmt.Printf("  (metrics unavailable: %v)\n", err)
	}

	st.report(elapsed)

	// Exit with error code if error rate > 5%
	if st.errors > 0 && float64(st.errors)/float64(st.total) > 0.05 {
		fmt.Fprintf(os.Stderr, "\nFAIL: error rate %.1f%% exceeds 5%% threshold\n",
			float64(st.errors)/float64(st.total)*100)
		os.Exit(1)
	}
}
