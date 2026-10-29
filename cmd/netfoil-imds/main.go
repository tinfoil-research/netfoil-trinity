package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/tinfoil-research/netfoil-trinity/internal/seccomp"
	"github.com/tinfoil-research/netfoil-trinity/internal/server"
	"golang.org/x/sys/unix"
)

const usage = `SYNOPSIS
    netfoil-imds [OPTIONS]

OPTIONS
        --ip
            IP to listen on (default: 192.168.122.1).

        --port
            TCP port to listen on (default: 8081).

        --config-directory
            Config directory (default: /etc/netfoil/imds/default).

        --filter-system-calls
            Apply seccomp filter for system calls (default: false, only supported on x86_64).`

func main() {
	options, err := processInput()
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	caHandler, err := NewCAHandler(options.ConfigDirectory)
	if err != nil {
		println(err.Error())
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
	mux.HandleFunc("/ca", caHandler.caHandle)

	server := &http.Server{
		Handler: mux,
	}

	fmt.Printf("ready...\n")
	err = server.Serve(tcpListener)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}
}

type Options struct {
	IP                net.IP
	Port              int
	ConfigDirectory   string
	FilterSystemCalls bool
}

func processInput() (*Options, error) {
	flags := flag.NewFlagSet("all", flag.ExitOnError)
	var help, h, filterSystemCalls bool

	var configPath, ipString string
	var portInt int
	flags.BoolVar(&help, "help", false, "")
	flags.BoolVar(&h, "h", false, "")
	flags.IntVar(&portInt, "port", 8081, "")
	flags.StringVar(&ipString, "ip", "192.168.122.1", "")
	flags.StringVar(&configPath, "config-directory", "/etc/netfoil/imds/default", "")
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
	}, nil
}

type CAHandler struct {
	caData []byte
}

func NewCAHandler(configDirectory string) (*CAHandler, error) {
	configPath := filepath.Join(configDirectory, "ca.crt")
	caData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	return &CAHandler{caData: caData}, nil
}

func (h *CAHandler) caHandle(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write(h.caData)
	if err != nil {
		fmt.Printf("error writing CA data: %s\n", err)
	}
}

func applySystemCallFilter(filter bool) error {
	if filter {
		err := seccomp.SetNoNewPrivs()
		if err != nil {
			return err
		}

		allowedSyscalls := []uint32{
			// TCP
			unix.SYS_ACCEPT4,
			unix.SYS_GETSOCKNAME,
			unix.SYS_SETSOCKOPT,
		}

		argumentFilters := seccomp.ArgumentFilters{
			SocketIPv4TCPUDP: false,
		}

		err = seccomp.ApplyFilter(allowedSyscalls, argumentFilters)
		if err != nil {
			return err
		}
	}

	return nil
}
