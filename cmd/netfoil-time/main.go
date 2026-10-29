package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/tinfoil-research/netfoil-trinity/internal/seccomp"
	"github.com/tinfoil-research/netfoil-trinity/internal/server"
	"github.com/tinfoil-research/netfoil-trinity/internal/time"
	"golang.org/x/sys/unix"
)

const usage = `SYNOPSIS
    netfoil-time [OPTIONS]

OPTIONS
        --ip
            IP to listen on (default: 192.168.122.1).

        --port
            TCP port to listen on (default: 8123).

        --config-directory
            Config directory (default: /etc/netfoil/time/default).

        --filter-system-calls
            Apply seccomp filter for system calls (default: false, only supported on x86_64).`

func main() {
	options, err := processInput()
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	conn, err := server.ResolveUDPListener(options.IP, options.Port)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	err = applySystemCallFilter(options.FilterSystemCalls)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	process(conn)
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
	flags.IntVar(&portInt, "port", 8123, "")
	flags.StringVar(&ipString, "ip", "192.168.122.1", "")
	flags.StringVar(&configPath, "config-directory", "/etc/netfoil/time/default", "")
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

func process(conn *net.UDPConn) {
	for {
		buf := make([]byte, 1024)
		responseLength, remote, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			err = fmt.Errorf("error: reading from UDP: %w\n", err)
			continue
		}

		fmt.Printf("request from %s\n", remote.String())
		response, err := processSNTP(buf[:responseLength])
		if err != nil {
			println(err.Error())
		}

		n, err := conn.WriteToUDP(response, remote)
		if err != nil {
			println(err.Error())
		}
		if n != len(response) {
			println("failed to write to UDP")
		}
	}
}

func processSNTP(data []byte) ([]byte, error) {
	packet, err := time.Decode(data)
	if err != nil {
		return nil, err
	}

	nowSeconds, nowFraction := time.Now()
	responsePacket := time.Packet{
		// TODO
		LeapIndicator: 0,
		VersionNumber: packet.VersionNumber,

		// Server
		Mode: 4,

		// 1 is primary
		Stratum: 2,

		Poll: packet.Poll,

		// ~1 microsecond
		Precision: -18,

		RootDelaySeconds: 0,
		// ~microsecond
		RootDelayFraction: 2,

		RootDispersionSeconds: 0,
		// ~microsecond
		RootDispersionFraction: 1,

		ReferenceID:                "XNT",
		ReferenceTimestampFraction: 0,
		ReferenceTimestampSeconds:  0,
		OriginTimestampSeconds:     packet.TransmitTimestampSeconds,
		OriginTimestampFraction:    packet.TransmitTimestampFraction,
		ReceiveTimestampSeconds:    nowSeconds,
		ReceiveTimestampFraction:   nowFraction,
		TransmitTimestampSeconds:   nowSeconds,
		TransmitTimestampFraction:  nowFraction,
	}

	result, err := time.Encode(responsePacket)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func applySystemCallFilter(filter bool) error {
	if filter {
		err := seccomp.SetNoNewPrivs()
		if err != nil {
			return err
		}

		allowedSyscalls := []uint32{
			// UDP
			unix.SYS_ACCEPT4,
			unix.SYS_GETSOCKNAME,
			unix.SYS_SETSOCKOPT,
			unix.SYS_RECVFROM,
			unix.SYS_SENDTO,
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
