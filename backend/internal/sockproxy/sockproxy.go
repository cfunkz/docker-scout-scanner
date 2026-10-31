// Package sockproxy is a tiny read-only filter in front of the Docker socket.
// It replaces a separate haproxy-based socket proxy image so the stack ships
// one less third-party image (and its OS packages / CVEs).
//
// Only GET/HEAD requests to the handful of endpoints the scanner, Trivy and
// Grype need are forwarded; everything else (exec, container archives and
// logs, any POST/DELETE, swarm, secrets, ...) is refused with 403.
package sockproxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// allowed matches decoded, cleaned request paths (optional /vX.Y API prefix).
var allowed = regexp.MustCompile(`^(/v[0-9]+\.[0-9]+)?/(_ping|version|info|events|containers/json|images/json|images/get|images/.+/(json|history|get))$`)

// Allowed reports whether a request may be forwarded. It returns the path that
// must be sent upstream (decoded and cleaned, so what was checked is what the
// daemon sees).
func Allowed(method string, u *url.URL) (string, bool) {
	if method != http.MethodGet && method != http.MethodHead {
		return "", false
	}
	p := u.Path // already percent-decoded by net/url
	if p == "" || strings.Contains(p, "\\") || strings.Contains(p, "\x00") {
		return "", false
	}
	if path.Clean(p) != p {
		return "", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return "", false
		}
	}
	if !allowed.MatchString(p) {
		return "", false
	}
	return p, true
}

// Handler returns the filtering reverse proxy for a Docker unix socket.
func Handler(socket string, log *slog.Logger) http.Handler {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    16,
		IdleConnTimeout: 90 * time.Second,
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "docker"
			pr.Out.Host = "docker"
		},
		Transport:     tr,
		FlushInterval: -1, // stream /events and image exports immediately
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() == nil {
				log.Warn("docker socket error", "path", r.URL.Path, "err", err)
			}
			http.Error(w, "docker unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := Allowed(r.Method, r.URL)
		if !ok {
			log.Warn("denied docker API call", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			http.Error(w, "forbidden by scanner socket proxy", http.StatusForbidden)
			return
		}
		r.URL.Path, r.URL.RawPath = p, ""
		r.Body = http.NoBody
		r.ContentLength = 0
		rp.ServeHTTP(w, r)
	})
}
