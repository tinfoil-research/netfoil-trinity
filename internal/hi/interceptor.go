package hi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tinfoil-research/netfoil-trinity/internal/filters"
)

type Interceptor struct {
	filters          map[string]filters.Filter
	client           *http.Client
	certs            sync.Map
	caCert           *x509.Certificate
	caPrivateKey     *ecdsa.PrivateKey
	domainPrivateKey *ecdsa.PrivateKey
	logChannel       chan<- handlerLog
}

type handlerLog struct {
	log string
}

func NewInterceptor(configDirectory string, clientCACertPool *x509.CertPool, caKeyData []byte) (*Interceptor, error) {
	config, err := ReadConfigFile(configDirectory)
	if err != nil {
		return nil, err
	}

	client, err := NewClient(clientCACertPool)
	if err != nil {
		return nil, err
	}

	caCert, caPrivateKey, err := loadCA(configDirectory, caKeyData)
	if err != nil {
		return nil, err
	}

	domainPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	filterMap := map[string]filters.Filter{}

	if config.EnableDebian {
		debianConfig, err := readConfig(configDirectory, filepath.Join("providers", "debian"))
		if err != nil {
			return nil, err
		}

		debianFilter, err := filters.NewDebianFilter(debianConfig)
		if err != nil {
			return nil, err
		}

		filterMap["deb.debian.org"] = debianFilter
		filterMap["security.debian.org"] = debianFilter
	}

	if config.EnableUbuntu {
		ubuntuConfig, err := readConfig(configDirectory, filepath.Join("providers", "ubuntu"))
		if err != nil {
			return nil, err
		}

		ubuntuFilter, err := filters.NewUbuntuFilter(ubuntuConfig)
		if err != nil {
			return nil, err
		}

		filterMap["archive.ubuntu.com"] = ubuntuFilter
		filterMap["security.ubuntu.com"] = ubuntuFilter
	}

	if config.EnableFedora {
		fedoraConfig, err := readConfig(configDirectory, filepath.Join("providers", "fedora"))
		if err != nil {
			return nil, err
		}

		fedoraFilter, err := filters.NewFedoraFilter(fedoraConfig, config.FedoraRepoPrefix)
		if err != nil {
			return nil, err
		}

		filterMap[config.FedoraRepoPrefix.Host] = fedoraFilter
	}

	if config.EnableGitHub {
		gitHubConfig, err := readConfig(configDirectory, filepath.Join("providers", "github"))
		if err != nil {
			return nil, err
		}

		gitHubFilter, err := filters.NewGitHubFilter(gitHubConfig)
		if err != nil {
			return nil, err
		}

		filterMap["github.com"] = gitHubFilter
	}

	if config.EnableGo {
		goConfig, err := readConfig(configDirectory, filepath.Join("providers", "go"))
		if err != nil {
			return nil, err
		}

		goFilter, err := filters.NewGoFilter(goConfig)
		if err != nil {
			return nil, err
		}

		filterMap["proxy.golang.org"] = goFilter
		filterMap["sum.golang.org"] = goFilter
	}

	if config.EnableDocker {
		dockerConfig, err := readConfig(configDirectory, filepath.Join("providers", "docker"))
		if err != nil {
			return nil, err
		}

		dockerFilter, err := filters.NewDockerFilter(dockerConfig)
		if err != nil {
			return nil, err
		}

		filterMap["registry-1.docker.io"] = dockerFilter
		filterMap["auth.docker.io"] = dockerFilter
		filterMap["production.cloudfront.docker.com"] = dockerFilter
	}

	m, err := filters.LoadAllGeneric(configDirectory)
	if err != nil {
		return nil, err
	}

	for k, v := range m {
		filterMap[k] = v
	}

	logChannel := make(chan handlerLog, 50)

	interceptor := Interceptor{
		filters:          filterMap,
		client:           client,
		certs:            sync.Map{},
		caCert:           caCert,
		caPrivateKey:     caPrivateKey,
		domainPrivateKey: domainPrivateKey,
		logChannel:       logChannel,
	}

	go func() {
		for log := range logChannel {
			fmt.Print(log.log)
		}
	}()

	return &interceptor, nil
}

func (i *Interceptor) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	fmt.Printf("cert %s\n", clientHello.ServerName)

	cert, found := i.certs.Load(clientHello.ServerName)
	if !found {
		var err error
		cert, err = i.createAndStoreCertificate(clientHello.ServerName)
		if err != nil {
			return nil, err
		}
	}

	return cert.(*tls.Certificate), nil
}

func (i *Interceptor) Handler(w http.ResponseWriter, r *http.Request) {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("%s %s\n", r.Method, r.Host+r.URL.String()))

	if r.TLS.ServerName != r.Host {
		sb.WriteString(fmt.Sprintf("domain mismatch\n"))
		w.WriteHeader(403)

		i.logChannel <- handlerLog{
			log: sb.String(),
		}
		return
	}

	for key, value := range r.Header {
		sb.WriteString(fmt.Sprintf("  %s: %s\n", key, strings.Join(value, ", ")))
	}

	filter, found := i.filters[r.Host]
	if !found {
		sb.WriteString(fmt.Sprintf("domain not allowed\n"))
		w.WriteHeader(403)

		i.logChannel <- handlerLog{
			log: sb.String(),
		}
		return
	}

	r.URL.Scheme = "https"
	r.URL.Host = r.Host

	r, allowed := filter.Transform(r)
	if !allowed {
		sb.WriteString(fmt.Sprintf("request not allowed\n"))
		w.WriteHeader(403)

		i.logChannel <- handlerLog{
			log: sb.String(),
		}
		return
	}

	r.RequestURI = ""

	response, err := i.client.Do(r)
	if err != nil {
		sb.WriteString(fmt.Sprintf("upstream call failed: %s\n", err.Error()))
		w.WriteHeader(500)

		i.logChannel <- handlerLog{
			log: sb.String(),
		}
		return
	}
	defer response.Body.Close()

	sb.WriteString(fmt.Sprintf("\n  StatusCode: %d\n", response.StatusCode))
	for key, values := range response.Header {
		if strings.ToLower(key) == "set-cookie" {
			continue
		}

		for _, value := range values {
			w.Header().Add(key, value)
			sb.WriteString(fmt.Sprintf("  %s: %s\n", key, strings.Join(values, ", ")))
		}
	}

	data, err := io.ReadAll(response.Body)
	if err != nil {
		sb.WriteString(fmt.Sprintf("upstream call failed: %s\n", err.Error()))

		i.logChannel <- handlerLog{
			log: sb.String(),
		}
		return
	}

	w.WriteHeader(response.StatusCode)
	_, err = w.Write(data)
	if err != nil {
		sb.WriteString(fmt.Sprintf("response copy failed: %s\n", err.Error()))

		i.logChannel <- handlerLog{
			log: sb.String(),
		}
		return
	}

	i.logChannel <- handlerLog{
		log: sb.String(),
	}
}

func (i *Interceptor) ConnState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
	case http.StateClosed:
	}

}

func (i *Interceptor) createAndStoreCertificate(domain string) (*tls.Certificate, error) {
	cert, err := createDomainCert(domain, i.caCert, i.caPrivateKey, i.domainPrivateKey)
	if err != nil {
		fmt.Printf("error creating certificate for domain '%s': %s\n", domain, err)
		return nil, err
	}

	i.certs.Store(domain, cert)

	return cert, nil
}
