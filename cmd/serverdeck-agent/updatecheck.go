package main

import (
	"errors"
	"os"
	"time"
)

// The single place the agent is allowed to touch apt's package cache.
//
// Everything on the refresh path reads from the caches these functions write.
// apt costs roughly 77 MB peak and several seconds per invocation, which is
// most of a small instance's free memory, so it runs only when the user
// explicitly asks — see the Updates tab on the Software page.

// Timestamps travel as RFC3339 strings, matching every other agent payload.
// Empty means no check has ever run, which the app shows differently from a
// check that found nothing.
type updateCheckResult struct {
	Packages    []updatePackage `json:"packages"`
	CollectedAt string          `json:"collected_at"`
	// Refreshed reports whether apt's index was updated as part of this check.
	Refreshed bool `json:"refreshed"`
}

func formatCollectedAt(value time.Time, ok bool) string {
	if !ok || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

// checkForUpdates refreshes apt's index, then recollects both the upgradable
// list and the candidate versions the software catalogue displays.
func checkForUpdates(refreshIndex bool) (updateCheckResult, error) {
	if refreshIndex {
		if os.Geteuid() != 0 {
			return updateCheckResult{}, errors.New("refreshing the package index requires root")
		}
		// A failure here is not fatal: a stale index still yields a usable
		// answer, and reporting one beats failing the whole check because a
		// single mirror was briefly unreachable.
		_, _ = apt(longTimeout, "apt-get", "update")
	}

	packages, err := collectUpgradable()
	if err != nil {
		return updateCheckResult{}, err
	}
	writeUpdateCache(updateCacheEntry{CollectedAt: time.Now(), Packages: packages})

	// Refresh the catalogue's candidate versions in the same pass, so the
	// Catalog tab stops showing stale "update available" markers.
	writeCandidateCache(packageCandidates(softwareCatalogPackageNames()))

	return updateCheckResult{
		Packages:    packages,
		CollectedAt: formatCollectedAt(cacheCollectedAt()),
		Refreshed:   refreshIndex,
	}, nil
}

// updateStatus reports what is currently known without touching apt.
func updateStatus() updateCheckResult {
	packages, ok := cachedUpgradableReadOnly()
	if !ok {
		return updateCheckResult{Packages: []updatePackage{}}
	}
	return updateCheckResult{Packages: packages, CollectedAt: formatCollectedAt(cacheCollectedAt())}
}
