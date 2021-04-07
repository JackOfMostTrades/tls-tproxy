package dns

import (
	"testing"
	"time"
)

func TestDnsCache(t *testing.T) {
	cache := NewDnsCache()

	expiry := time.Now().Add(60 * time.Second)

	cache.AddAlias("service.example.com", "elb-name.example.com", expiry)
	cache.AddAlias("elb-name.example.com", "192.168.0.1", expiry)
	hostnames := cache.GetAliasesForName("192.168.0.1")
	if !setEquals(hostnames, []string{"elb-name.example.com", "service.example.com"}) {
		t.Errorf("unexpected hostnames: %v", hostnames)
	}
}

func TestPruneCache(t *testing.T) {
	cache := NewDnsCache()

	expired := time.Now().Add(-1 * time.Second)
	notExpired := time.Now().Add(60 * time.Second)
	cache.AddAlias("service.example.com", "192.168.0.1", expired)
	cache.AddAlias("apples.example.com", "192.168.0.2", notExpired)
	cache.PruneCache()

	if !setEquals(cache.GetAliasesForName("192.168.0.1"), []string{}) {
		t.Errorf("cache should have removed expired entry.")
	}
	if !setEquals(cache.GetAliasesForName("192.168.0.2"), []string{"apples.example.com"}) {
		t.Errorf("cache should not have removed non-expired entry.")
	}
}

func setEquals(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	x := toSet(a)
	y := toSet(b)
	if len(x) != len(y) {
		return false
	}
	for k := range x {
		if _, ok := y[k]; !ok {
			return false
		}
	}
	return true
}

func toSet(a []string) map[string]bool {
	s := make(map[string]bool)
	for _, val := range a {
		s[val] = true
	}
	return s
}
