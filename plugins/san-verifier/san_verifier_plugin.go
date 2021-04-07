package san_verifier

import (
	"crypto/x509"
	"fmt"
	"github.com/jackofmosttrades/tls-tproxy/plugin"
)

type SanVerifierPlugin struct {
}

func init() {
	plugin.Register(&SanVerifierPlugin{})
}

func (p *SanVerifierPlugin) Name() string {
	return "san_verifier"
}

func (p *SanVerifierPlugin) Init() error {
	return nil
}

func (p *SanVerifierPlugin) GetCertChecker() plugin.CertChecker {
	return func(hostnames []string, cert *x509.Certificate) error {
		for _, hostname := range hostnames {
			err := cert.VerifyHostname(hostname)
			if err == nil {
				return nil
			}
		}
		return fmt.Errorf("none of the expected hostnames were in the certificate: %v", hostnames)
	}
}
