package hi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"
)

func NewClient(caCertPool *x509.CertPool) (*http.Client, error) {
	timeout := 60 * time.Second

	tlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		NextProtos: []string{"h2", "http/1.1"},
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	httpTransport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       timeout,
		ResponseHeaderTimeout: timeout,
		TLSHandshakeTimeout:   timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}

	client := http.Client{
		Transport: httpTransport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &client, nil
}
