package sockproxy

import (
	"net/url"
	"testing"
)

func TestAllowed(t *testing.T) {
	cases := []struct {
		method, raw string
		ok          bool
	}{
		{"GET", "/_ping", true},
		{"HEAD", "/_ping", true},
		{"GET", "/v1.47/version", true},
		{"GET", "/v1.47/info", true},
		{"GET", "/v1.47/events?filters=%7B%7D", true},
		{"GET", "/v1.47/containers/json?all=1", true},
		{"GET", "/v1.47/images/json", true},
		{"GET", "/v1.47/images/sha256:abc/json", true},
		{"GET", "/v1.47/images/ghcr.io/org/app:1.2/json", true},
		{"GET", "/v1.47/images/nginx%3Alatest/history", true},
		{"GET", "/v1.47/images/nginx:latest/get", true},
		{"GET", "/v1.56/images/get?names=sha256%3Aabc", true},
		{"POST", "/v1.47/images/create", false},
		{"POST", "/v1.47/containers/create", false},
		{"DELETE", "/v1.47/images/nginx", false},
		{"GET", "/v1.47/containers/abc/json", false},
		{"GET", "/v1.47/containers/abc/archive?path=/etc", false},
		{"GET", "/v1.47/containers/abc/logs", false},
		{"GET", "/v1.47/containers/abc/export", false},
		{"GET", "/v1.47/secrets", false},
		{"GET", "/v1.47/images/x/../../containers/abc/export", false},
		{"GET", "/v1.47/images/x%2F..%2F..%2Fcontainers%2Fabc%2Fexport/json", false},
		{"GET", "/v1.47/images/x/..%2F..%2Fcontainers/abc/json", false},
		{"GET", "//_ping", false},
		{"GET", "/v1.47/images/json/", false},
	}
	for _, c := range cases {
		u, err := url.Parse(c.raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := Allowed(c.method, u); ok != c.ok {
			t.Errorf("%s %s: got %v want %v", c.method, c.raw, ok, c.ok)
		}
	}
}
