package plugin

import "crypto/x509"

type Plugin interface {
	Name() string
	Init() error
}

type CertChecker func(hostnames []string, cert *x509.Certificate) error

type CertCheckerPlugin interface {
	GetCertChecker() CertChecker
}

var _REGISTERED_PLUGINS []Plugin

func Register(plugin Plugin) {
	_REGISTERED_PLUGINS = append(_REGISTERED_PLUGINS, plugin)
}

func List() []Plugin {
	return _REGISTERED_PLUGINS
}
