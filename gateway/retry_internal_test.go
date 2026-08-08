package gateway

import (
	"crypto/x509"
	"net/url"
	"testing"
)

func TestRetryableTransportErrorRejectsPermanentTLSVerificationFailure(t *testing.T) {
	err := &url.Error{
		Op:  "Post",
		URL: "https://upstream.invalid/mcp",
		Err: x509.UnknownAuthorityError{},
	}
	if retryableTransportError(err) {
		t.Fatal("permanent TLS certificate verification error was retryable")
	}
}
