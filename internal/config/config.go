// Package config loads and validates MCP Gateway runtime configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxTimeout = 5 * time.Minute

// Values is the complete typed runtime configuration.
type Values struct {
	UpstreamURL     string
	ListenAddress   string
	UpstreamTimeout time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
}

// Load reads required settings using getenv and validates them before startup.
func Load(getenv func(string) string) (Values, error) {
	if getenv == nil {
		return Values{}, errors.New("configuration source is required")
	}
	values := Values{
		UpstreamURL:   strings.TrimSpace(getenv("MCP_GATEWAY_UPSTREAM_URL")),
		ListenAddress: strings.TrimSpace(getenv("MCP_GATEWAY_LISTEN_ADDRESS")),
	}
	upstream, err := url.ParseRequestURI(values.UpstreamURL)
	if err != nil || upstream.Hostname() == "" || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.User != nil {
		return Values{}, errors.New("MCP_GATEWAY_UPSTREAM_URL must be an absolute HTTP(S) URL without user information")
	}
	_, portText, err := net.SplitHostPort(values.ListenAddress)
	if err != nil {
		return Values{}, errors.New("MCP_GATEWAY_LISTEN_ADDRESS must be a host:port address")
	}
	if portText == "" || strings.IndexFunc(portText, func(character rune) bool {
		return character < '0' || character > '9'
	}) != -1 {
		return Values{}, errors.New("MCP_GATEWAY_LISTEN_ADDRESS port must contain only digits")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return Values{}, errors.New("MCP_GATEWAY_LISTEN_ADDRESS port must be a number from 1 to 65535")
	}

	for _, item := range []struct {
		name   string
		target *time.Duration
	}{
		{"MCP_GATEWAY_UPSTREAM_TIMEOUT", &values.UpstreamTimeout},
		{"MCP_GATEWAY_READ_TIMEOUT", &values.ReadTimeout},
		{"MCP_GATEWAY_WRITE_TIMEOUT", &values.WriteTimeout},
		{"MCP_GATEWAY_IDLE_TIMEOUT", &values.IdleTimeout},
	} {
		duration, err := time.ParseDuration(strings.TrimSpace(getenv(item.name)))
		if err != nil || duration <= 0 || duration > maxTimeout {
			return Values{}, fmt.Errorf("%s must be a positive duration no greater than %s", item.name, maxTimeout)
		}
		*item.target = duration
	}
	return values, nil
}
