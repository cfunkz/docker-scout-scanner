package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
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

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck())
		case "reset-password":
			os.Exit(resetPassword(os.Args[2:]))
		case "socket-proxy":
			os.Exit(socketProxy())
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
			log.Info("listening", "addr", s.Addr)
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
		url = "http://127.0.0.1:2375/_ping"
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

// socketProxy runs the read-only Docker API filter (see internal/sockproxy).
func socketProxy() int {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level()}))
	sock := os.Getenv("DOCKER_SOCKET")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":2375"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           sockproxy.Handler(sock, log),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("docker socket proxy listening (read-only allowlist)", "addr", addr, "socket", sock)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("socket proxy", "err", err)
		return 1
	}
	return 0
}
