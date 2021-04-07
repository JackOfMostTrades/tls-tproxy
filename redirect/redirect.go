package redirect

import (
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"github.com/sirupsen/logrus"
	"os"
	"strconv"
	"strings"
)

func cleanup(logger *logrus.Logger, ipt *iptables.IPTables) error {
	rules, err := ipt.List("nat", "OUTPUT")
	if err != nil {
		return fmt.Errorf("unable to list current iptable rules: %v", err)
	}
	for _, rule := range rules {
		parts := strings.Split(rule, " ")
		if parts[0] != "-A" || parts[1] != "OUTPUT" {
			continue
		}
		for i := 0; i < len(parts)-1; i++ {
			if parts[i] == "--comment" && strings.HasPrefix(parts[i+1], "tls-tproxy-") {
				logger.Debugf("Deleting iptables rule from nat/OUTPUT: %s", rule)
				err = ipt.Delete("nat", "OUTPUT", parts[2:]...)
				if err != nil {
					return fmt.Errorf("Failed to delete iptables rule: %v", err)
				}
			}
		}
	}

	return nil
}

func Cleanup(logger *logrus.Logger) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return fmt.Errorf("unable to initialize iptables: %v", err)
	}
	return cleanup(logger, ipt)
}

func Setup(logger *logrus.Logger, listenerPort int, portMap map[uint16]uint16) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return fmt.Errorf("unable to initialize iptables: %v", err)
	}
	err = cleanup(logger, ipt)
	if err != nil {
		return err
	}
	pid := os.Getpid()

	for srcPort := range portMap {
		err = ipt.Append("nat", "OUTPUT", "-p", "tcp",
			"-m", "owner", "!", "--uid-owner", "root",
			"--dport", strconv.Itoa(int(srcPort)),
			"-m", "comment", "--comment", fmt.Sprintf("tls-tproxy-%d", pid), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", listenerPort))
		if err != nil {
			return fmt.Errorf("failed to add iptables rule: %v", err)
		}
	}
	return nil
}
