package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	_ "time/tzdata" // TZ support without OS packages

	"github.com/cfunkz/docker-scout-scanner/backend/internal/api"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/config"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/docker"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/engine"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/scanner"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/sockproxy"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/store"
	"github.com/cfunkz/docker-scout-scanner/backend/internal/tlsgen"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	api.Version = version
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version":
			fmt.Println(version)
			return
		case "healthcheck":
			os.Exit(healthcheck())
		case "reset-password":
			os.Exit(resetPassword(os.Args[2:]))
		case "reset-2fa":
			os.Exit(reset2FA(os.Args[2:]))
		case "socket-proxy":
			os.Exit(socketProxy())
		case "agent-certs":
			os.Exit(agentCerts(os.Args[2:]))
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level()}))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func level() slog.Level {
	if os.Getenv("LOG_LEVEL") == "debug" {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

func run(log *slog.Logger) error {
	env := config.LoadEnv()
	for _, d := range []string{env.DataDir, filepath.Join(env.DataDir, "sbom"), filepath.Join(env.DataDir, "cache", "trivy"), filepath.Join(env.DataDir, "cache", "grype")} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}

	// Temporary files (image exports while Trivy reads them can be several GB)
	// go to the data volume, not a RAM-backed /tmp that counts against the
	// container's memory limit. Leftovers from a crash are cleared on start.
	if os.Getenv("SCAN_TMPDIR") != "memory" {
		tmp := filepath.Join(env.DataDir, "tmp")
		_ = os.RemoveAll(tmp)
		if err := os.MkdirAll(tmp, 0o700); err != nil {
			return err
		}
		os.Setenv("TMPDIR", tmp)
	}

	// TLS material for nginx: generated once unless the user mounted their own.
	if env.CertDir != "" {
		created, err := tlsgen.Ensure(env.CertDir, env.TLSSANs)
		if err != nil {
			return fmt.Errorf("TLS cert: %w", err)
		}
		if created {
			log.Info("generated self-signed TLS certificate", "dir", env.CertDir, "sans", env.TLSSANs)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(filepath.Join(env.DataDir, "scanner.db"))
	if err != nil {
		return err
	}
	defer st.DB.Close()

	if err := api.Bootstrap(ctx, st, env.DataDir, func(msg string, args ...any) { log.Warn(msg, args...) }); err != nil {
		return err
	}
	cfg, err := config.NewManager(ctx, st)
	if err != nil {
		return err
	}
	dk, err := docker.New(env.DockerHost)
	if err != nil {
		return err
	}
	eng := &engine.Runner{
		TrivyBin:   env.TrivyBin,
		GrypeBin:   env.GrypeBin,
		CacheDir:   filepath.Join(env.DataDir, "cache", "trivy"),
		GrypeCache: filepath.Join(env.DataDir, "cache", "grype"),
		SBOMDir:    filepath.Join(env.DataDir, "sbom"),
		DockerHost: env.DockerHost,
	}
	sc := scanner.New(st, cfg, dk, eng, log)
	srv := api.New(st, cfg, sc, eng, env, log)

	servers := []*http.Server{
		newServer(env.PublicAddr, srv.PublicHandler()),
		newServer(env.AdminAddr, srv.AdminHandler()),
	}
	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func(s *http.Server) {
			log.Info("listening", "addr", s.Addr, "version", version)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}(s)
	}
	go sc.Run(ctx)

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(sctx)
	}
	return nil
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}

func healthcheck() int {
	addr := os.Getenv("PUBLIC_ADDR")
	if addr == "" {
		addr = ":8000"
	}
	if addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	url := "http://" + addr + "/api/health"
	if os.Getenv("HEALTH_PING") != "" { // socket-proxy mode
		if os.Getenv("TLS_CERT") != "" { // agent with mutual TLS: just check the port
			c, err := net.DialTimeout("tcp", "127.0.0.1"+listenAddr(), 3*time.Second)
			if err != nil {
				return 1
			}
			c.Close()
			return 0
		}
		url = "http://127.0.0.1" + listenAddr() + "/_ping"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return 1
	}
	return 0
}

// resetPassword is a break-glass command: docker compose exec scanner scanner reset-password admin
func resetPassword(args []string) int {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: scanner reset-password <username>")
		return 2
	}
	env := config.LoadEnv()
	st, err := store.Open(filepath.Join(env.DataDir, "scanner.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx := context.Background()
	u, _ := st.UserByName(ctx, fs.Arg(0))
	if u == nil {
		fmt.Fprintln(os.Stderr, "no such user")
		return 1
	}
	pw := api.RandomPassword()
	h, _ := api.HashPassword(pw)
	if err := st.SetPassword(ctx, u.ID, h, true); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	st.DeleteUserSessions(ctx, u.ID, "")
	st.Audit(ctx, "cli", "", "user_password_reset", u.Username)
	fmt.Printf("New temporary password for %s: %s\n(you will be asked to change it at login)\n", u.Username, pw)
	return 0
}

// reset2FA turns off two-factor sign-in for a user who lost their phone and
// their recovery codes.
func reset2FA(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: scanner reset-2fa <username>")
		return 2
	}
	env := config.LoadEnv()
	st, err := store.Open(filepath.Join(env.DataDir, "scanner.db"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx := context.Background()
	u, _ := st.UserByName(ctx, args[0])
	if u == nil {
		fmt.Fprintln(os.Stderr, "no such user")
		return 1
	}
	if err := st.DeleteTOTP(ctx, u.ID); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	st.Audit(ctx, "cli", "", "user_2fa_reset", u.Username)
	fmt.Printf("Two-factor sign-in turned off for %s. They can set it up again under Settings.\n", u.Username)
	return 0
}

// socketProxy runs the read-only Docker API filter (see internal/sockproxy).
func socketProxy() int {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level()}))
	sock := os.Getenv("DOCKER_SOCKET")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	addr := listenAddr()
	srv := &http.Server{
		Addr:              addr,
		Handler:           sockproxy.Handler(sock, log),
		ReadHeaderTimeout: 10 * time.Second,
	}
	// Remote agent mode: TLS with a required client certificate from our own
	// CA (see `scanner agent-certs`), the same scheme Docker uses for tcp://.
	certFile, keyFile, caFile := os.Getenv("TLS_CERT"), os.Getenv("TLS_KEY"), os.Getenv("TLS_CA")
	if certFile != "" {
		ca, err := os.ReadFile(caFile)
		pool := x509.NewCertPool()
		if err != nil || !pool.AppendCertsFromPEM(ca) {
			log.Error("TLS_CA must point to the agent's ca.pem", "file", caFile, "err", err)
			return 1
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
		// The container healthcheck only opens the port; don't log that as a
		// failed handshake every 30 seconds. Other handshake errors still show.
		srv.ErrorLog = stdlog.New(dropLocal{os.Stderr}, "", stdlog.LstdFlags)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("docker socket proxy listening (read-only allowlist)", "addr", addr, "socket", sock, "mutual_tls", certFile != "")
	var err error
	if certFile != "" {
		err = srv.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("socket proxy", "err", err)
		return 1
	}
	return 0
}

func listenAddr() string {
	if a := os.Getenv("LISTEN_ADDR"); a != "" {
		return a
	}
	return ":2375"
}

// agentCerts writes the mutual-TLS files for a remote agent:
// scanner agent-certs -out /data/agent-certs nas.lan 192.168.1.20
func agentCerts(args []string) int {
	fs := flag.NewFlagSet("agent-certs", flag.ExitOnError)
	out := fs.String("out", "agent-certs", "output folder")
	years := fs.Int("years", 5, "validity in years")
	_ = fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: scanner agent-certs [-out dir] <remote hostname or IP>...")
		return 2
	}
	if err := tlsgen.RemoteCerts(*out, fs.Args(), *years); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if os.Getuid() == 0 { // run via scanner.sh: hand the client key to the scanner's user
		dir := filepath.Join(*out, "scanner")
		for _, f := range []string{"", "ca.pem", "cert.pem", "key.pem"} {
			_ = os.Chown(filepath.Join(dir, f), 10001, 10001)
		}
	}
	fmt.Printf("wrote %s/agent (copy to the remote host) and %s/scanner (for this scanner)\n", *out, *out)
	return 0
}

type dropLocal struct{ w io.Writer }

func (d dropLocal) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("from 127.0.0.1:")) {
		return len(p), nil
	}
	return d.w.Write(p)
}
