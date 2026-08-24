package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouterRoutesByHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-Host"); got != "vm1.local:8080" {
			t.Fatalf("unexpected X-Forwarded-Host: %q", got)
		}

		if got := r.Header.Get("X-Forwarded-Proto"); got != "http" {
			t.Fatalf("unexpected X-Forwarded-Proto: %q", got)
		}

		_, _ = w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	handler, err := newRouter(config{
		Routes: []route{{Host: "vm1.local", Target: upstream.URL}},
	})
	if err != nil {
		t.Fatalf("newRouter returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/", nil)
	req.Host = "vm1.local:8080"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", recorder.Code)
	}

	if got := recorder.Body.String(); got != "proxied" {
		t.Fatalf("unexpected body: %q", got)
	}
}

func TestRouterReturnsNotFoundForUnknownHost(t *testing.T) {
	handler, err := newRouter(config{
		Routes: []route{{Host: "vm1.local", Target: "http://127.0.0.1:9000"}},
	})
	if err != nil {
		t.Fatalf("newRouter returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/", nil)
	req.Host = "vm2.local"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unexpected status code: %d", recorder.Code)
	}
}

func TestHealthz(t *testing.T) {
	handler, err := newRouter(config{
		Routes: []route{{Host: "vm1.local", Target: "http://127.0.0.1:9000"}},
	})
	if err != nil {
		t.Fatalf("newRouter returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/healthz", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status code: %d", recorder.Code)
	}

	body, err := io.ReadAll(recorder.Result().Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "ok" {
		t.Fatalf("unexpected body: %q", string(body))
	}
}
