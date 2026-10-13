package hi

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func loadCA(configDirectory string, caKeyData []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caPath := filepath.Join(configDirectory, "ca.crt")
	caData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, nil, err
	}

	caDecoded, _ := pem.Decode(caData)
	if caDecoded == nil || caDecoded.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode CA data")
	}

	ca, err := x509.ParseCertificate(caDecoded.Bytes)
	if err != nil {
		return nil, nil, err
	}

	caKeyDecoded, _ := pem.Decode(caKeyData)
	if caKeyDecoded == nil || caKeyDecoded.Type != "PRIVATE KEY" {
		return nil, nil, fmt.Errorf("failed to decode CA key")
	}

	key, err := x509.ParsePKCS8PrivateKey(caKeyDecoded.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return ca, key.(*ecdsa.PrivateKey), nil
}

func createDomainCert(domain string, caCert *x509.Certificate, caPrivateKey *ecdsa.PrivateKey, domainPrivateKey *ecdsa.PrivateKey) (*tls.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"Tinfoil"},
		},
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(24 * time.Hour * 365),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		DNSNames:  []string{domain},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &domainPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes})

	privateKeyBytes, err := x509.MarshalECPrivateKey(domainPrivateKey)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	cert, err := tls.X509KeyPair(certPEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return &cert, nil
}
