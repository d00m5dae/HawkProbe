package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetrySucceedsAfterTransientErrors(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	}))
	defer srv.Close()

	opts := testOptions()
	opts.Retries = 2
	client, err := newClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	var requests int64
	resp, body, err := fetchBody(context.Background(), client, opts, http.MethodGet, srv.URL, nil, 64*1024, &requests)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "ok") {
		t.Fatalf("unexpected response %d %q", resp.StatusCode, body)
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
}

func TestRetryExhausted(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	opts := testOptions()
	opts.Retries = 1
	client, err := newClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	var requests int64
	_, _, err = fetchBody(context.Background(), client, opts, http.MethodGet, srv.URL, nil, 64*1024, &requests)
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected 2 attempts, got %d", calls)
	}
}

func TestRetryRespectsZeroRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	opts := testOptions()
	opts.Retries = 0
	client, err := newClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	var requests int64
	_, _, err = fetchBody(context.Background(), client, opts, http.MethodGet, srv.URL, nil, 64*1024, &requests)
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected exactly 1 attempt, got %d", calls)
	}
}

func TestMaxRequestsBudgetStopsRuleScan(t *testing.T) {
	var hits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprintln(w, "page")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	opts := testOptions()
	opts.Retries = 0
	opts.MaxRequests = 2
	rules := []rule{
		{ID: "a", Path: "/a", Name: "a", Severity: "info", Statuses: []int{200}},
		{ID: "b", Path: "/b", Name: "b", Severity: "info", Statuses: []int{200}},
		{ID: "c", Path: "/c", Name: "c", Severity: "info", Statuses: []int{200}},
	}
	result := scanTarget(opts, srv.URL, rules, nil)
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.Requests > opts.MaxRequests {
		t.Fatalf("budget exceeded: %d > %d", result.Requests, opts.MaxRequests)
	}
	if result.Skipped < 1 {
		t.Fatalf("expected at least one skipped rule, stats=%+v", result)
	}
	if int(atomic.LoadInt32(&hits)) > opts.MaxRequests {
		t.Fatalf("server saw %d requests, budget was %d", hits, opts.MaxRequests)
	}
}

func TestBudgetExhaustedErrorIsDistinct(t *testing.T) {
	if !errors.Is(errBudgetExhausted, errBudgetExhausted) {
		t.Fatal("sentinel should match itself")
	}
}

func TestTransientStatusClassification(t *testing.T) {
	for _, code := range []int{502, 503, 504} {
		if !isTransientStatus(code) {
			t.Fatalf("%d should be transient", code)
		}
	}
	for _, code := range []int{200, 301, 404, 500} {
		if isTransientStatus(code) {
			t.Fatalf("%d should not be transient", code)
		}
	}
}

func testOptions() options {
	return options{
		Mode:              "default",
		Concurrency:       4,
		TargetConcurrency: 1,
		Timeout:           5 * time.Second,
		MaxRedirects:      5,
	}
}
