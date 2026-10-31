// Package engine drives the external matchers (Trivy, Grype) and normalises
// their output.
//
// The pipeline is SBOM-first: an image is read from the Docker daemon exactly
// once (Trivy writes a CycloneDX SBOM), and every later match — by either
// engine, after every vulnerability-DB update — runs against that stored SBOM.
// A re-scan of an unchanged image therefore never touches the daemon and
// takes seconds even for multi-GB images.
package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Runner struct {
	TrivyBin   string
	GrypeBin   string
	CacheDir   string // trivy cache root
	GrypeCache string
	SBOMDir    string
	DockerHost string
}

func (r *Runner) env(offline bool) []string {
	env := os.Environ()
	env = append(env,
		"TRIVY_CACHE_DIR="+r.CacheDir,
		"TRIVY_NO_PROGRESS=true",
		"TRIVY_DISABLE_TELEMETRY=true",
		"TRIVY_SKIP_VERSION_CHECK=true",
		"TRIVY_DISABLE_VEX_NOTICE=true",
		"GRYPE_DB_CACHE_DIR="+r.GrypeCache,
		"GRYPE_CHECK_FOR_APP_UPDATE=false",
		"GRYPE_DB_AUTO_UPDATE=false",
		"GRYPE_DB_VALIDATE_AGE=false",
		"DOCKER_HOST="+r.DockerHost,
	)
	if offline {
		env = append(env, "TRIVY_OFFLINE_SCAN=true", "TRIVY_SKIP_JAVA_DB_UPDATE=true")
	}
	return env
}

func (r *Runner) run(ctx context.Context, offline bool, stdout io.Writer, bin string, args ...string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = r.env(offline)
	var stderr bytes.Buffer
	cmd.Stdout = stdout
	cmd.Stderr = &limitedBuffer{buf: &stderr, max: 16 << 10}
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		msg := lastLines(stderr.String(), 4)
		if ctx.Err() != nil {
			return fmt.Errorf("%s timed out", filepath.Base(bin))
		}
		return fmt.Errorf("%s: %v: %s", filepath.Base(bin), err, msg)
	}
	return nil
}

// HasGrype reports whether the grype binary is available.
func (r *Runner) HasGrype() bool {
	_, err := exec.LookPath(r.GrypeBin)
	return err == nil
}

// SBOMPath is where the compressed SBOM of an image lives.
func (r *Runner) SBOMPath(imageID string) string {
	return filepath.Join(r.SBOMDir, strings.TrimPrefix(imageID, "sha256:")+".cdx.json.gz")
}

// GenerateSBOM reads the image from the daemon and stores a gzipped CycloneDX SBOM.
func (r *Runner) GenerateSBOM(ctx context.Context, imageID string, offline bool) (string, error) {
	if err := os.MkdirAll(r.SBOMDir, 0o750); err != nil {
		return "", err
	}
	dst := r.SBOMPath(imageID)
	tmp, err := os.CreateTemp(r.SBOMDir, ".sbom-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	gz := gzip.NewWriter(tmp)
	err = r.run(ctx, offline, gz, r.TrivyBin, "image", "--quiet", "--image-src", "docker",
		"--format", "cyclonedx", "--scanners", "vuln", imageID)
	if cerr := gz.Close(); err == nil {
		err = cerr
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	return dst, os.Rename(tmp.Name(), dst)
}

// readSBOMTo decompresses the stored SBOM into a temp file that the engines can read.
func readSBOMTo(path string) (string, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", nil, err
	}
	tmp, err := os.CreateTemp("", "sbom-*.cdx.json")
	if err != nil {
		return "", nil, err
	}
	if _, err := io.Copy(tmp, gz); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", nil, err
	}
	tmp.Close()
	return tmp.Name(), func() { os.Remove(tmp.Name()) }, nil
}

// SBOMInfo extracts what we need from the SBOM: package count and a
// purl -> layer diffID map (Grype does not report layers for SBOM input).
type SBOMInfo struct {
	Packages int
	LayerOf  map[string]string
	OSFamily string
	OSName   string
}

func ReadSBOMInfo(path string) (*SBOMInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Components []struct {
			Type       string `json:"type"`
			Name       string `json:"name"`
			Version    string `json:"version"`
			PURL       string `json:"purl"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.NewDecoder(gz).Decode(&doc); err != nil {
		return nil, err
	}
	info := &SBOMInfo{LayerOf: map[string]string{}}
	for _, c := range doc.Components {
		if c.Type == "operating-system" {
			info.OSFamily, info.OSName = c.Name, c.Version
			continue
		}
		if c.PURL == "" {
			continue
		}
		info.Packages++
		for _, p := range c.Properties {
			if p.Name == "aquasecurity:trivy:LayerDiffID" {
				info.LayerOf[purlKey(c.PURL)] = p.Value
				info.LayerOf[c.Name+"@"+c.Version] = p.Value
			}
		}
	}
	return info, nil
}

// purlKey strips qualifiers so trivy- and grype-formatted purls compare equal.
func purlKey(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return strings.ToLower(p)
}

// ---------- DB management ----------

type DBStatus struct {
	Engine    string    `json:"engine"`
	Version   string    `json:"version"`
	DBBuilt   time.Time `json:"db_built"`
	DBUpdated time.Time `json:"db_updated"`
	Ready     bool      `json:"ready"`
	Error     string    `json:"error,omitempty"`
}

func (r *Runner) TrivyStatus(ctx context.Context) DBStatus {
	st := DBStatus{Engine: "trivy"}
	var out bytes.Buffer
	if err := r.run(ctx, true, &out, r.TrivyBin, "version", "--format", "json"); err != nil {
		st.Error = err.Error()
		return st
	}
	var v struct {
		Version         string
		VulnerabilityDB *struct {
			UpdatedAt    time.Time
			DownloadedAt time.Time
		}
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		st.Error = err.Error()
		return st
	}
	st.Version = v.Version
	if v.VulnerabilityDB != nil {
		st.DBBuilt, st.DBUpdated, st.Ready = v.VulnerabilityDB.UpdatedAt, v.VulnerabilityDB.DownloadedAt, true
	}
	return st
}

func (r *Runner) GrypeStatus(ctx context.Context) DBStatus {
	st := DBStatus{Engine: "grype"}
	if !r.HasGrype() {
		st.Error = "grype not installed"
		return st
	}
	var out bytes.Buffer
	if err := r.run(ctx, true, &out, r.GrypeBin, "version", "-o", "json"); err == nil {
		var v struct{ Version string }
		_ = json.Unmarshal(out.Bytes(), &v)
		st.Version = v.Version
	}
	out.Reset()
	if err := r.run(ctx, true, &out, r.GrypeBin, "db", "status", "-o", "json"); err != nil {
		st.Error = "no database yet"
		return st
	}
	var v struct {
		Built string `json:"built"`
		Valid bool   `json:"valid"`
		Path  string `json:"path"`
	}
	_ = json.Unmarshal(out.Bytes(), &v)
	st.DBBuilt, _ = time.Parse(time.RFC3339, v.Built)
	st.Ready = v.Valid
	if v.Path != "" {
		if fi, err := os.Stat(v.Path); err == nil {
			st.DBUpdated = fi.ModTime()
		}
	}
	return st
}

func (r *Runner) UpdateTrivyDB(ctx context.Context) error {
	return r.run(ctx, false, io.Discard, r.TrivyBin, "image", "--quiet", "--download-db-only")
}

func (r *Runner) UpdateGrypeDB(ctx context.Context) error {
	if !r.HasGrype() {
		return errors.New("grype not installed")
	}
	return r.run(ctx, false, io.Discard, r.GrypeBin, "db", "update")
}

// ---------- small utils ----------

type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
