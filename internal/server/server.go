package server

import (
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

const (
	UINT16_MAX = 65535
)

func ResolveTCPListener(ip net.IP, port int) (*net.TCPListener, error) {
	tcpListener, err := systemdTCPListener()
	if err != nil {
		println(err.Error())
	}

	if tcpListener == nil {
		tcpListener, err = bindTCPService(ip, port)
		if err != nil {
			println(err.Error())
			os.Exit(1)
		}
	}

	return tcpListener, nil
}

func systemdTCPListener() (*net.TCPListener, error) {
	if _, ok := os.LookupEnv("LISTEN_FDS"); ok {
		g := os.NewFile(uintptr(3), "netfoil.socket.tcp")
		tcpListener, err := net.FileListener(g)
		if err != nil {
			return nil, err
		}
		tcpListenerTyped := tcpListener.(*net.TCPListener)

		return tcpListenerTyped, nil
	}

	return nil, fmt.Errorf("systemd socket listener not configured")
}

func bindTCPService(ip net.IP, port int) (*net.TCPListener, error) {
	tcpAddr := net.TCPAddr{
		Port: port,
		IP:   ip,
	}
	tcpListener, err := net.ListenTCP("tcp", &tcpAddr)
	if err != nil {
		return nil, err
	}

	return tcpListener, nil
}

func ResolveUDPListener(ip net.IP, port int) (*net.UDPConn, error) {
	udpListener, err := systemdUDPListener()
	if err != nil {
		println(err.Error())
	}

	if udpListener == nil {
		udpListener, err = bindUDPService(ip, port)
		if err != nil {
			println(err.Error())
			os.Exit(1)
		}
	}

	return udpListener, nil
}

func systemdUDPListener() (*net.UDPConn, error) {
	if _, ok := os.LookupEnv("LISTEN_FDS"); ok {
		f := os.NewFile(uintptr(3), "netfoil.socket.udp")

		conn, err := net.FileConn(f)
		if err != nil {
			return nil, err
		}
		udpConnTyped := conn.(*net.UDPConn)

		return udpConnTyped, nil
	}

	return nil, fmt.Errorf("systemd socket listener not configured")
}

func bindUDPService(ip net.IP, port int) (*net.UDPConn, error) {
	addr := net.UDPAddr{
		Port: port,
		IP:   ip,
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, err
	}

	return conn, err
}

func LoadCACertificates() (*x509.CertPool, error) {
	caCert, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	if err != nil {
		return nil, fmt.Errorf("error reading CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("error parsing CA certificate")
	}

	return caCertPool, nil
}

func LoadSystemdCred(name string) ([]byte, error) {
	if d, ok := os.LookupEnv("CREDENTIALS_DIRECTORY"); ok {
		path := filepath.Join(d, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		return data, nil
	}

	return nil, fmt.Errorf("unable to load credential %s", name)
}
