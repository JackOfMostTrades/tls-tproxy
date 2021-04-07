package redirect

import (
	"os/exec"
	"strings"
)

func Setup(logger *logrus.Logger, listenerPort int, portMap map[uint16]uint16) error {
	srcPorts := make([]string, 0, len(portMap))
	for srcPort := range portMap {
		srcPorts = append(srcPorts, fmt.Sprintf("%d", srcPort))
	}

	cmd := exec.Command("/usr/sbin/pfctl", "-ef", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("rdr pass on en0 inet proto tcp from any to any port {%s} -> 127.0.0.1 port %d",
		strings.Join(srcPorts, ", "), listenerPort))
	err = cmd.Run()
	if err != nil {
		return err
	}
	err = cmd.Wait()
	if err != nil {
		return err
	}
	return nil
}

func Cleanup(logger *logrus.Logger) error {
	cmd := exec.Command("/usr/sbin/pfctl", "-d")
	err := cmd.Run()
	if err != nil {
		return err
	}
	err = cmd.Wait()
	if err != nil {
		return err
	}
	return nil
}
