package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

type config struct {
	Routes []route `json:"routes"`
}

type route struct {
	Host   string `json:"host"`
	Target string `json:"target"`
}

type router struct {
	proxies map[string]*httputil.ReverseProxy
}

func main() {
	listenAddr := envOrDefault("LISTEN_ADDR", ":8080")
	configPath := envOrDefault("CONFIG_PATH", "routes.json")

	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	handler, err := newRouter(cfg)
	if err != nil {
		log.Fatalf("build router: %v", err)
	}

	log.Printf("proxy router listening on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}

	return fallback
}

func loadConfig(path string) (config, error) {
	file, err := os.Open(path)
	if err != nil {
		return config{}, err
	}
	defer file.Close()

	var cfg config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return config{}, err
	}

	return cfg, nil
}

func newRouter(cfg config) (http.Handler, error) {
	if len(cfg.Routes) == 0 {
		return nil, errors.New("config must include at least one route")
	}

	proxies := make(map[string]*httputil.ReverseProxy, len(cfg.Routes))

	for _, entry := range cfg.Routes {
		host := normalizeHost(entry.Host)
		if host == "" {
			return nil, errors.New("route host must not be empty")
		}

		targetURL, err := url.Parse(entry.Target)
		if err != nil {
			return nil, fmt.Errorf("parse target for %s: %w", host, err)
		}

		if targetURL.Scheme == "" || targetURL.Host == "" {
			return nil, fmt.Errorf("target for %s must include scheme and host", host)
		}

		proxies[host] = newReverseProxy(targetURL)
	}

	return router{proxies: proxies}, nil
}

func newReverseProxy(target *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", forwardedProto(req))
	}

	return proxy
}

func (r router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	host := normalizeHost(req.Host)
	proxy, ok := r.proxies[host]
	if !ok {
		http.Error(w, "route not found", http.StatusNotFound)
		return
	}

	proxy.ServeHTTP(w, req)
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return parsedHost
	}

	return host
}

func forwardedProto(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}

	if header := strings.TrimSpace(req.Header.Get("X-Forwarded-Proto")); header != "" {
		return header
	}

	return "http"
}
