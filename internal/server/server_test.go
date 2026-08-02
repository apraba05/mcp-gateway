package server_test

import (
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/apraba05/mcp-gateway/internal/config"
	gatewayserver "github.com/apraba05/mcp-gateway/internal/server"
)

func TestNewAppliesBoundedHTTPServerConfiguration(t *testing.T) {
	t.Parallel()

	cfg := config.Values{
		ListenAddress: "127.0.0.1:8080",
		ReadTimeout:   2 * time.Second,
		WriteTimeout:  3 * time.Second,
		IdleTimeout:   4 * time.Second,
	}
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	got := gatewayserver.New(cfg, handler, slog.New(slog.NewJSONHandler(io.Discard, nil)))

	if got.Addr != cfg.ListenAddress || got.ReadTimeout != cfg.ReadTimeout || got.WriteTimeout != cfg.WriteTimeout || got.IdleTimeout != cfg.IdleTimeout {
		t.Errorf("server settings = %#v", got)
	}
	if got.ReadHeaderTimeout != cfg.ReadTimeout {
		t.Errorf("read header timeout = %s, want %s", got.ReadHeaderTimeout, cfg.ReadTimeout)
	}
}
