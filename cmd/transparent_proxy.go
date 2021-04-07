package cmd

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

const SO_ORIGINAL_DST = 80

// https://github.com/ryanchapman/go-any-proxy/blob/master/any_proxy.go
func getOriginalDst(clientConn *net.TCPConn) (string, uint16, error) {
	if clientConn == nil {
		return "", 0, errors.New("clientConn is nil")
	}

	clientConnFile, err := clientConn.File()
	if err != nil {
		return "", 0, err
	}
	defer clientConnFile.Close()

	// Get original destination
	// this is the only syscall in the Golang libs that I can find that returns 16 bytes
	// Example result: &{Multiaddr:[2 0 31 144 206 190 36 45 0 0 0 0 0 0 0 0] Interface:0}
	// port starts at the 3rd byte and is 2 bytes long (31 144 = port 8080)
	// IPv4 address starts at the 5th byte, 4 bytes long (206 190 36 45)
	var addr *syscall.IPv6Mreq
	addr, err = syscall.GetsockoptIPv6Mreq(int(clientConnFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		return "", 0, err
	}

	ipv4 := fmt.Sprintf("%d.%d.%d.%d",
		uint(addr.Multiaddr[4]),
		uint(addr.Multiaddr[5]),
		uint(addr.Multiaddr[6]),
		uint(addr.Multiaddr[7]))
	port := uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])

	return ipv4, port, nil
}
