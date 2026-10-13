package hi

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"
)

func NewClient(caCertPool *x509.CertPool) (*http.Client, error) {
	timeout := 30 * time.Second

	tlsConfig := &tls.Config{}
	tlsConfig.RootCAs = caCertPool

	httpTransport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		IdleConnTimeout:       timeout,
		ResponseHeaderTimeout: timeout,
		TLSHandshakeTimeout:   timeout,
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
