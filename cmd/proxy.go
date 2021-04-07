package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/jackofmosttrades/tls-tproxy/dns"
	"github.com/jackofmosttrades/tls-tproxy/plugin"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"sync"
	"time"
)

type Proxy struct {
	logger      *logrus.Logger
	dnsCache    *dns.DnsCache
	rootCAs     *x509.CertPool
	certLoader  *cachedCertificateLoader
	certChecker plugin.CertChecker
}

func (p *Proxy) Run() (func(), error) {
	listener, err := net.Listen("tcp", "localhost:8003")
	if err != nil {
		return nil, err
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer p.logger.Infof("Proxy shutting down...")

		for {
			conn, err := listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				p.logger.Errorf("Got error accepting connection: %v", err)
				continue
			}
			go p.handleConn(conn)
		}
	}()

	return func() { listener.Close(); wg.Wait() }, nil
}

func (p *Proxy) handleConn(conn net.Conn) {
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		p.logger.Errorf("Got non-TCP connection: %T", conn)
		return
	}
	ipv4, port, err := getOriginalDst(tcpConn)
	if err != nil {
		p.logger.Errorf("Unable to resolve original destination of connection: %v", err)
		return
	}
	if port < 10000 {
		p.logger.Errorf("Unexpect original target port: %d", port)
		return
	}
	targetPort := port - 10000

	hostnames := p.dnsCache.GetAliasesForName(ipv4)
	if len(hostnames) == 0 {
		// Wait 1 second for captured packets to make their way into the DNS cache...
		time.Sleep(1 * time.Second)

		hostnames = p.dnsCache.GetAliasesForName(ipv4)
		if len(hostnames) == 0 {
			p.logger.Errorf("Found no DNS lookups for target IP %s", ipv4)
			return
		}
	}
	p.logger.Tracef("Found DNS lookups for IP %s => %v", ipv4, hostnames)

	tlsConfig := &tls.Config{
		RootCAs:            p.rootCAs,
		InsecureSkipVerify: true,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return p.certLoader.GetCertificate()
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Based on the golang verification code. See https://golang.org/src/crypto/tls/handshake_client.go
			certs := make([]*x509.Certificate, len(rawCerts))
			for i, asn1Data := range rawCerts {
				cert, err := x509.ParseCertificate(asn1Data)
				if err != nil {
					return errors.New("proxy: failed to parse certificate from server: " + err.Error())
				}
				certs[i] = cert
			}

			opts := x509.VerifyOptions{
				Roots:         p.rootCAs,
				Intermediates: x509.NewCertPool(),
			}
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := certs[0].Verify(opts)
			if err != nil {
				return err
			}

			err = p.certChecker(hostnames, certs[0])
			if err != nil {
				return err
			}

			return nil
		},
	}

	targetConn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", ipv4, targetPort), tlsConfig)
	if err != nil {
		p.logger.Errorf("Failed to dial target %s:%d: %v", ipv4, targetPort, err)
		return
	}

	// Copy data between the two connections
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() { io.Copy(targetConn, conn); wg.Done() }()
	io.Copy(conn, targetConn)
	wg.Wait()
}
