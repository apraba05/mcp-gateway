package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apraba05/mcp-gateway/gateway"
	"github.com/apraba05/mcp-gateway/internal/config"
	gatewayserver "github.com/apraba05/mcp-gateway/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	handler, err := gateway.New(gateway.Config{
		UpstreamURL:     cfg.UpstreamURL,
		UpstreamTimeout: cfg.UpstreamTimeout,
		Logger:          logger,
	})
	if err != nil {
		logger.Error("initialize gateway", "error", err)
		os.Exit(1)
	}

	server := gatewayserver.New(cfg, handler, logger)
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("gateway listening", "address", cfg.ListenAddress)
		serverErrors <- server.ListenAndServe()
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("gateway stopped", "error", err)
			os.Exit(1)
		}
	case sig := <-signals:
		logger.Info("shutdown requested", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			_ = server.Close()
			os.Exit(1)
		}
	}
}
