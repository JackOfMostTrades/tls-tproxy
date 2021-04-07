package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/jackofmosttrades/tls-tproxy/dns"
	"github.com/jackofmosttrades/tls-tproxy/plugin"
	"github.com/jackofmosttrades/tls-tproxy/redirect"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	_ "github.com/jackofmosttrades/tls-tproxy/plugins/san-verifier"
)

func Main() {
	fs := flag.NewFlagSet("tls-tproxy", flag.ContinueOnError)

	var caCertPath string
	fs.StringVar(&caCertPath, "cacert", "", "Path to CA bundle file (PEM/X509). Uses system trust store by default.")
	var certPath string
	fs.StringVar(&certPath, "cert", "", "Path to certificate (PEM with certificate chain).")
	var keyPath string
	fs.StringVar(&keyPath, "key", "", "Path to certificate private key (PEM with private key).")
	var logLevelStr string
	fs.StringVar(&logLevelStr, "logLevel", "info", fmt.Sprintf("Level to log: possible values: %v", logrus.AllLevels))
	var portMapStr string
	fs.StringVar(&portMapStr, "portMap", "8443:443", "Port mapping to use, in the format of src1:dst1,src2:dst2,... Plaintext traffic sent on port src1 will be wrapped with TLS and sent to the target IP on port dst1. The source and destintation ports can be the same.")
	var certCheckerPlugin string
	fs.StringVar(&certCheckerPlugin, "certCheckerPlugin", "san_verifier", "The plugin name to use for verifying certificates.")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		panic(err)
	}

	logLevel, err := logrus.ParseLevel(logLevelStr)
	if err != nil {
		panic(err)
	}

	logger := logrus.StandardLogger()
	logger.SetLevel(logLevel)

	portMap := make(map[uint16]uint16)
	for _, portMapPart := range strings.Split(portMapStr, ",") {
		vals := strings.SplitN(portMapPart, ":", 2)
		if len(vals) != 2 {
			logger.Errorf("Invalid portMap argument: %s", portMapStr)
			return
		}
		src, err := strconv.Atoi(vals[0])
		if err != nil {
			logger.Errorf("Invalid portMap argument: %s", portMapStr)
			return
		}
		dst, err := strconv.Atoi(vals[1])
		if err != nil {
			logger.Errorf("Invalid portMap argument: %s", portMapStr)
			return
		}
		portMap[uint16(src)] = uint16(dst)
	}

	var caCert *x509.CertPool
	if caCertPath != "" {
		caCert = x509.NewCertPool()
		caCertBytes, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			logger.Errorf("Failed to read cacert path %s: %v", caCertPath, err)
			return
		}
		block, rest := pem.Decode(caCertBytes)
		for block != nil {
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					logger.Errorf("Failed to parse certificate in cacert path %s: %v", caCertPath, err)
					return
				}
				caCert.AddCert(cert)
			}
			block, rest = pem.Decode(rest)
		}
	}

	certLoader, err := NewCertificateLoader(certPath, keyPath)
	if err != nil {
		logger.Errorf("Failed to load cert/key: cert=%s, key=%s: %v", certPath, keyPath, err)
		return
	}

	dnsCapture := dns.NewCapture(logger)
	close, err := dnsCapture.Run()
	if err != nil {
		panic(err)
	}
	defer close()

	var certChecker plugin.CertChecker
	for _, p := range plugin.List() {
		if p.Name() == certCheckerPlugin {
			if ccp, ok := p.(plugin.CertCheckerPlugin); ok {
				certChecker = ccp.GetCertChecker()
			} else {
				logger.Errorf("Specified certificate checker plugin %s does not implement the CertCheckerPlugin interface: %T", certCheckerPlugin, ccp)
				return
			}
		}
	}
	if certChecker == nil {
		logger.Errorf("Specified certificate checker plugin %s was not found.", certCheckerPlugin)
		return
	}

	proxy := &Proxy{
		logger:      logger,
		dnsCache:    dnsCapture.GetCache(),
		rootCAs:     caCert,
		certLoader:  certLoader,
		certChecker: certChecker,
		portMap:     portMap,
	}
	stop, listenerPort, err := proxy.Run()
	if err != nil {
		panic(err)
	}
	defer stop()

	logger.Debugf("Transparent proxy listening for redirected traffic on port %d", listenerPort)

	err = redirect.Setup(logger, listenerPort, portMap)
	if err != nil {
		logger.Errorf("Failed to initialize iptables redirect of plaintext connections: %v", err)
		return
	}
	defer func() {
		logger.Debugf("Cleaning up iptables redirect...")
		err := redirect.Cleanup(logger)
		if err != nil {
			logger.Errorf("Error cleaning up iptables redirect: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Executing clean shutdown...")
}
