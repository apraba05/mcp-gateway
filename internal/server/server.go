// Package server constructs the bounded HTTP server used by MCP Gateway.
package server

import (
	"log/slog"
	"net/http"

	"github.com/apraba05/mcp-gateway/internal/config"
)

// New creates an HTTP server with explicit read, write, idle, and header limits.
func New(cfg config.Values, handler http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           handler,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
}
