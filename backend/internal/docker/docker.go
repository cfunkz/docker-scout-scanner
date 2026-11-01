// Package docker is a tiny read-only Docker Engine API client. It only needs
// GET endpoints, so it works through a locked-down docker-socket-proxy.
package docker

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Client struct {
	http *http.Client
	base string
}

func New(host string) (*Client, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second}
	base := ""
	switch u.Scheme {
	case "unix":
		sock := u.Path
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}
		base = "http://docker"
	case "tcp", "http", "https":
		base = "http://" + u.Host
		// Docker's own convention: DOCKER_TLS_VERIFY=1 and DOCKER_CERT_PATH
		// with ca.pem, cert.pem and key.pem (mutual TLS to a remote agent).
		certDir := os.Getenv("DOCKER_CERT_PATH")
		if u.Scheme == "https" || os.Getenv("DOCKER_TLS_VERIFY") != "" || certDir != "" {
			tc, err := clientTLS(certDir, u.Hostname())
			if err != nil {
				return nil, err
			}
			tr.TLSClientConfig = tc
			base = "https://" + u.Host
		}
	default:
		return nil, fmt.Errorf("unsupported DOCKER_HOST %q", host)
	}
	return &Client{http: &http.Client{Transport: tr}, base: base}, nil
}

func clientTLS(dir, server string) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: server}
	if dir == "" {
		return tc, nil
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, fmt.Errorf("DOCKER_CERT_PATH: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("DOCKER_CERT_PATH: no certificate in ca.pem")
	}
	tc.RootCAs = pool
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, fmt.Errorf("DOCKER_CERT_PATH: %w", err)
	}
	tc.Certificates = []tls.Certificate{cert}
	return tc, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("docker %s: %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type ImageSummary struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	Created     int64    `json:"Created"`
	Size        int64    `json:"Size"`
}

func (c *Client) Images(ctx context.Context) ([]ImageSummary, error) {
	var out []ImageSummary
	err := c.get(ctx, "/images/json", &out)
	for i := range out {
		tags := out[i].RepoTags[:0]
		for _, t := range out[i].RepoTags {
			if t != "<none>:<none>" {
				tags = append(tags, t)
			}
		}
		out[i].RepoTags = tags
		ds := out[i].RepoDigests[:0]
		for _, d := range out[i].RepoDigests {
			if d != "<none>@<none>" {
				ds = append(ds, d)
			}
		}
		out[i].RepoDigests = ds
	}
	return out, err
}

type ContainerSummary struct {
	ID      string   `json:"Id"`
	Names   []string `json:"Names"`
	ImageID string   `json:"ImageID"`
	State   string   `json:"State"`
}

func (c *Client) Containers(ctx context.Context) ([]ContainerSummary, error) {
	var out []ContainerSummary
	err := c.get(ctx, "/containers/json?all=1", &out)
	return out, err
}

type ImageInspect struct {
	ID           string `json:"Id"`
	Os           string `json:"Os"`
	Architecture string `json:"Architecture"`
	RootFS       struct {
		Layers []string `json:"Layers"`
	} `json:"RootFS"`
}

func (c *Client) Inspect(ctx context.Context, id string) (*ImageInspect, error) {
	var out ImageInspect
	err := c.get(ctx, "/images/"+url.PathEscape(id)+"/json", &out)
	return &out, err
}

type HistoryItem struct {
	ID        string `json:"Id"`
	Created   int64  `json:"Created"`
	CreatedBy string `json:"CreatedBy"`
	Size      int64  `json:"Size"`
	Comment   string `json:"Comment"`
}

func (c *Client) History(ctx context.Context, id string) ([]HistoryItem, error) {
	var out []HistoryItem
	err := c.get(ctx, "/images/"+url.PathEscape(id)+"/history", &out)
	return out, err
}

func (c *Client) Ping(ctx context.Context) error {
	var v struct {
		Version string `json:"Version"`
	}
	return c.get(ctx, "/version", &v)
}

type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
}

// Events streams image and container events until ctx is cancelled or the stream breaks.
func (c *Client) Events(ctx context.Context, fn func(Event)) error {
	filters := url.QueryEscape(`{"type":["image","container"]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/events?filters="+filters, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("events: %s", resp.Status)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var ev Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil {
			fn(ev)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.EOF
}
