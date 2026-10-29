package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tinfoil-research/netfoil-trinity/internal/hi"
	"github.com/tinfoil-research/netfoil-trinity/internal/seccomp"
	"github.com/tinfoil-research/netfoil-trinity/internal/server"
	"golang.org/x/sys/unix"
)

const usage = `SYNOPSIS
    netfoil-hi [OPTIONS]

OPTIONS
        --ip
            IP to listen on (default: 192.168.122.1).

        --port
            TCP port to listen on (default: 8080).

        --config-directory
            Config directory (default: /etc/netfoil/hi/default).

        --ca-key
            Name of systemd credential with CA key

        --filter-system-calls
            Apply seccomp filter for system calls (default: false, only supported on x86_64).`

func main() {
	options, err := processInput()
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	// This is just to initialize Go's DNS resolver before we apply the seccomp filter
	_, err = net.LookupHost("localhost")
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	clientCACertPool, err := server.LoadCACertificates()
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	caKeyData, err := server.LoadSystemdCred(options.CAKeyName)
	if err != nil {
		caKeyPath := filepath.Join(options.ConfigDirectory, "ca.key")
		caKeyData, err = os.ReadFile(caKeyPath)
		if err != nil {
			println(err.Error())
			os.Exit(1)
		}
	}

	interceptor, err := hi.NewInterceptor(options.ConfigDirectory, clientCACertPool, caKeyData)
	if err != nil {
		print(err.Error(), "\n")
		os.Exit(1)
	}

	tcpListener, err := server.ResolveTCPListener(options.IP, options.Port)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}
	defer tcpListener.Close()

	err = applySystemCallFilter(options.FilterSystemCalls)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{name...}", interceptor.Handler)

	tlsConfig := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: interceptor.GetCertificate,
	}

	timeout := 60 * time.Second
	server := &http.Server{
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		ConnState:    interceptor.ConnState,
	}

	fmt.Println("ready...")
	err = server.ServeTLS(tcpListener, "", "")
	if err != nil {
		print(err.Error(), "\n")
		os.Exit(1)
	}
}

type Options struct {
	IP                net.IP
	Port              int
	ConfigDirectory   string
	FilterSystemCalls bool
	CAKeyName         string
}

func processInput() (*Options, error) {
	flags := flag.NewFlagSet("all", flag.ExitOnError)
	var help, h, filterSystemCalls bool

	var configPath, ipString, caKeyName string
	var portInt int
	flags.BoolVar(&help, "help", false, "")
	flags.BoolVar(&h, "h", false, "")
	flags.IntVar(&portInt, "port", 8080, "")
	flags.StringVar(&ipString, "ip", "192.168.122.1", "")
	flags.StringVar(&configPath, "config-directory", "/etc/netfoil/hi/default", "")
	flags.StringVar(&caKeyName, "ca-key", "netfoil-hi-ca", "")
	flags.BoolVar(&filterSystemCalls, "filter-system-calls", false, "")

	err := flags.Parse(os.Args[1:])
	if err != nil || help || h {
		fmt.Println(usage)
		os.Exit(1)
	}

	if portInt < 0 || portInt > server.UINT16_MAX {
		return nil, fmt.Errorf("invalid port %d", portInt)
	}

	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipString)
	}

	return &Options{
		IP:                ip,
		Port:              portInt,
		ConfigDirectory:   configPath,
		FilterSystemCalls: filterSystemCalls,
		CAKeyName:         caKeyName,
	}, nil
}

func applySystemCallFilter(filter bool) error {
	if filter {
		err := seccomp.SetNoNewPrivs()
		if err != nil {
			return err
		}

		allowedSyscalls := []uint32{
			// UDP and TCP
			unix.SYS_ACCEPT4,
			unix.SYS_CONNECT,
			unix.SYS_GETPEERNAME,
			unix.SYS_GETSOCKNAME,
			unix.SYS_GETSOCKOPT,
			unix.SYS_SETSOCKOPT,
			unix.SYS_RECVFROM,
			unix.SYS_SENDTO,

			// TODO
			unix.SYS_UNAME,

			unix.SYS_NEWFSTATAT,
		}

		argumentFilters := seccomp.ArgumentFilters{
			SocketIPv4TCPUDP: true,
		}

		err = seccomp.ApplyFilter(allowedSyscalls, argumentFilters)
		if err != nil {
			return err
		}
	}

	return nil
}
