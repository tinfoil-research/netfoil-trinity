package hi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
)

func NewClient(caCertPool *x509.CertPool) (*http.Client, error) {
	tlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		NextProtos: []string{"h2", "http/1.1"},
	}

	dialer := &net.Dialer{}

	httpTransport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}

	client := http.Client{
		Transport: httpTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &client, nil
}
