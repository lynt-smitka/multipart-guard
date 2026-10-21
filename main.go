package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/multipart-guard/config", "path to the config file")
	check := flag.Bool("check", false, "validate the config and exit")
	showVer := flag.Bool("version", false, "print version")
	flag.Parse()

	if *showVer {
		fmt.Println("multipart-guard", version)
		return
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}
	if *check {
		fmt.Printf("config OK: listen=%s mode=%s upstream=%s:%d/%d max_body=%d spool=%s log=%s\n",
			cfg.Listen, cfg.Mode, cfg.UpstreamHost, cfg.UpstreamPortHTTP, cfg.UpstreamPortHTTPS, cfg.MaxBody, cfg.SpoolDir, cfg.LogFile)
		return
	}

	// Part header limits of mime/multipart are set via GODEBUG (Go 1.21+ re-reads it after os.Setenv).
	godebug := os.Getenv("GODEBUG")
	if godebug != "" {
		godebug += ","
	}
	godebug += "multipartmaxheadersize=" + strconv.Itoa(cfg.MaxPartHeaderSize*2) +
		",multipartmaxheaders=" + strconv.Itoa(cfg.MaxPartHeaders*4)
	os.Setenv("GODEBUG", godebug)

	if err := os.MkdirAll(cfg.SpoolDir, 0700); err != nil {
		fmt.Fprintln(os.Stderr, "spool_dir:", err)
		os.Exit(2)
	}
	probe, err := os.CreateTemp(cfg.SpoolDir, "probe-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "spool_dir is not writable:", err)
		os.Exit(2)
	}
	probe.Close()
	os.Remove(probe.Name())

	lg, err := newLogger(cfg.LogFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "log:", err)
		os.Exit(2)
	}
	defer lg.Close()

	if cfg.PidFile != "" {
		if err := os.WriteFile(cfg.PidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644); err != nil {
			fmt.Fprintln(os.Stderr, "pidfile:", err)
			os.Exit(2)
		}
		defer os.Remove(cfg.PidFile)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}

	g := newGuard(cfg, lg)
	srv := &http.Server{
		Handler:           g,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.BodyTimeout,
		WriteTimeout:      cfg.BodyTimeout + cfg.UpstreamTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    64 << 10,
	}
	srv.SetKeepAlivesEnabled(true)

	lg.Log(&Entry{Event: "info", Msg: fmt.Sprintf("start %s listen=%s mode=%s upstream=%s max_body=%d", version, cfg.Listen, cfg.Mode, cfg.UpstreamHost, cfg.MaxBody)})

	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for s := range sigs {
			switch s {
			case syscall.SIGHUP:
				if err := lg.reopen(); err != nil {
					fmt.Fprintln(os.Stderr, "reopen log:", err)
				}
				lg.Info("log reopened (SIGHUP)")
			default:
				lg.Info("shutting down (" + s.String() + ")")
				ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
				srv.Shutdown(ctx)
				cancel()
				return
			}
		}
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
	time.Sleep(50 * time.Millisecond)
}
