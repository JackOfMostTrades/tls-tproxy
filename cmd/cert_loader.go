package cmd

import (
	"crypto/tls"
	"time"
)

type cachedCertificateLoader struct {
	certPath    string
	keyPath     string
	certificate *tls.Certificate
	nextReload  time.Time
}

func NewCertificateLoader(certPath string, keyPath string) (*cachedCertificateLoader, error) {
	loader := &cachedCertificateLoader{
		certPath: certPath,
		keyPath:  keyPath,
	}
	_, err := loader.GetCertificate()
	if err != nil {
		return nil, err
	}
	return loader, nil
}

func (c *cachedCertificateLoader) GetCertificate() (*tls.Certificate, error) {
	now := time.Now()
	if now.After(c.nextReload) {
		cert, err := tls.LoadX509KeyPair(c.certPath, c.keyPath)
		if err != nil {
			return nil, err
		}
		c.certificate = &cert
		c.nextReload = now.Add(1 * time.Hour)
	}
	return c.certificate, nil
}
