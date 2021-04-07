package dns

import (
	"sync"
	"time"
)

type aliasEntry struct {
	alias  string
	expiry time.Time
}

type reverseCacheEntry struct {
	values []aliasEntry
}

type DnsCache struct {
	mutex            sync.RWMutex
	reverseNameCache map[string]*reverseCacheEntry
}

func NewDnsCache() *DnsCache {
	return &DnsCache{
		mutex:            sync.RWMutex{},
		reverseNameCache: make(map[string]*reverseCacheEntry),
	}
}

func (c *DnsCache) GetAliasesForName(name string) []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, ok := c.reverseNameCache[name]
	if !ok {
		return nil
	}
	now := time.Now()

	aliases := make([]string, 0, len(entry.values))
	for _, val := range entry.values {
		if now.After(val.expiry) {
			continue
		}
		aliases = append(aliases, val.alias)
	}
	return aliases
}

func (c *DnsCache) PruneCache() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for key, entry := range c.reverseNameCache {
		validEntries := make([]aliasEntry, 0, len(entry.values))
		for _, val := range entry.values {
			if now.Before(val.expiry) {
				validEntries = append(validEntries, val)
			}
		}
		if len(validEntries) == 0 {
			delete(c.reverseNameCache, key)
			continue
		}
		if len(validEntries) != len(entry.values) {
			entry.values = validEntries
		}
	}
}

func (c *DnsCache) AddAlias(alias string, name string, expiry time.Time) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	entry, ok := c.reverseNameCache[name]
	if !ok {
		entry = &reverseCacheEntry{}
		c.reverseNameCache[name] = entry
	}
	// Add this direct alias
	entry.values = append(entry.values, aliasEntry{
		alias:  alias,
		expiry: expiry,
	})
	// If alias itself has aliases, add all of those indirect aliases
	if indirectAlias, ok := c.reverseNameCache[alias]; ok {
		for _, val := range indirectAlias.values {
			entry.values = append(entry.values, aliasEntry{
				alias:  val.alias,
				expiry: expiry,
			})
		}
	}
}
