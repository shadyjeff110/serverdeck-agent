package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// Cached view of `apt list --upgradable`.
//
// That command parses the whole package cache and is one of the most expensive
// things the agent runs. It was previously executed three times per refresh —
// once by the app's own probe script, once by listSystemUpdates, and once more
// while assembling the security summary — with every invocation a separate
// process on a box the user chose ServerDeck to avoid loading.
//
// The refresh path now only ever reads this cache; apt runs solely when the user
// taps Check for Updates. The collection time travels with the data so the app
// can show how fresh it is rather than silently refreshing behind the user.
// Each agent invocation is its own process, so the cache has to live on disk.
const (
	updateCacheDir  = "/var/lib/serverdeck/cache"
	updateCachePath = updateCacheDir + "/upgradable.json"
)

type updateCacheEntry struct {
	CollectedAt time.Time       `json:"collectedAt"`
	Packages    []updatePackage `json:"packages"`
}

func readUpdateCacheIgnoringAge() (updateCacheEntry, bool) {
	contents, err := os.ReadFile(updateCachePath)
	if err != nil {
		return updateCacheEntry{}, false
	}
	var entry updateCacheEntry
	if json.Unmarshal(contents, &entry) != nil {
		return updateCacheEntry{}, false
	}
	return entry, true
}

func writeUpdateCache(entry updateCacheEntry) {
	if os.MkdirAll(updateCacheDir, 0755) != nil {
		return
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return
	}
	// Best effort: a cache write failing must never fail the caller.
	_ = atomicWrite(updateCachePath, append(encoded, '\n'), 0644)
}

// invalidateUpdateCache drops the cached list after an operation that changes
// it, so the next read reflects reality instead of waiting out the TTL.
func invalidateUpdateCache() {
	_ = os.Remove(updateCachePath)
}

// collectUpgradable runs the actual apt query.
func collectUpgradable() ([]updatePackage, error) {
	output, err := apt(defaultTimeout, "apt", "list", "--upgradable")
	if err != nil {
		return nil, err
	}
	return parseUpgradable(string(output)), nil
}

func parseUpgradable(output string) []updatePackage {
	values := []updatePackage{}
	for _, line := range strings.Split(output, "\n") {
		match := upgradablePattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) == 4 {
			values = append(values, updatePackage{Name: match[1], Candidate: match[2], Current: match[3]})
		}
	}
	return values
}

// cachedUpgradableReadOnly returns whatever is cached and never runs apt.
//
// This is what the refresh path uses. cachedUpgradable would fall back to
// running apt when the cache is cold, which is exactly the ~77 MB spike that
// must never be triggered implicitly — apt runs only when the user asks for it.
func cachedUpgradableReadOnly() ([]updatePackage, bool) {
	entry, ok := readUpdateCacheIgnoringAge()
	if !ok {
		return nil, false
	}
	return entry.Packages, true
}

// cachedUpgradableCount is the cheap path for callers that only need a number.
// Returns -1 when nothing has been collected yet, which the app renders as
// "not checked" rather than a misleading zero.
func cachedUpgradableCount() int {
	packages, ok := cachedUpgradableReadOnly()
	if !ok {
		return -1
	}
	return len(packages)
}

// cacheAge reports how long ago the update list was collected.
func cacheCollectedAt() (time.Time, bool) {
	entry, ok := readUpdateCacheIgnoringAge()
	if !ok {
		return time.Time{}, false
	}
	return entry.CollectedAt, true
}

// --- Candidate version cache -------------------------------------------------

// Candidate versions come from apt-cache, which is as expensive as apt itself.
// The software catalogue needs them only to show "update available", so they are
// collected during an explicit update check and read from cache otherwise.
const candidateCachePath = updateCacheDir + "/candidates.json"

type candidateCacheEntry struct {
	CollectedAt time.Time         `json:"collectedAt"`
	Candidates  map[string]string `json:"candidates"`
}

func readCandidateCache() map[string]string {
	contents, err := os.ReadFile(candidateCachePath)
	if err != nil {
		return map[string]string{}
	}
	var entry candidateCacheEntry
	if json.Unmarshal(contents, &entry) != nil || entry.Candidates == nil {
		return map[string]string{}
	}
	return entry.Candidates
}

func writeCandidateCache(candidates map[string]string) {
	if os.MkdirAll(updateCacheDir, 0755) != nil {
		return
	}
	encoded, err := json.Marshal(candidateCacheEntry{CollectedAt: time.Now(), Candidates: candidates})
	if err != nil {
		return
	}
	_ = atomicWrite(candidateCachePath, append(encoded, '\n'), 0644)
}

func invalidateCandidateCache() {
	_ = os.Remove(candidateCachePath)
}
