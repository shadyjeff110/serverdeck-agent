package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Repository management.
//
// A third-party apt repository can replace any system package, so this is one of
// the most dangerous things the app can do to a server. The design constrains it
// deliberately rather than exposing apt's full flexibility:
//
//   - Curated entries (see packageSourceCatalog) can be toggled on and off. Their
//     URIs and signing keys are fixed in the agent, so there is nothing to typo.
//   - Beyond that, only Launchpad PPAs may be added, and only in the strict
//     `ppa:owner/name` form. add-apt-repository fetches the signing key from
//     Launchpad over HTTPS, so the key is never supplied by the user.
//
// Arbitrary `deb` lines and arbitrary key URLs are intentionally not supported.
// They are the shape that lets a mistyped or hostile entry silently take over
// package installation, and reviewing one properly is not something a user can
// reasonably do on a tablet.

// ppaPattern is deliberately strict: Launchpad owner and PPA names are limited
// to lowercase letters, digits, and the separators below.
var ppaPattern = regexp.MustCompile(`^ppa:[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*$`)

// managedSourceMarker identifies files this agent created, so disabling a
// repository can never remove one the user wrote by hand.
const managedSourceMarker = "# Managed by ServerDeck"

// addPPA registers a Launchpad PPA after validating its form.
func addPPA(reference string) ([]packageSource, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("adding a repository requires root")
	}
	reference = strings.TrimSpace(reference)
	if !ppaPattern.MatchString(reference) {
		return nil, fmt.Errorf("%q is not a valid PPA reference; expected the form ppa:owner/name", reference)
	}

	// software-properties-common provides add-apt-repository, which handles
	// Launchpad key retrieval. Installing it on demand keeps the base image lean.
	if _, err := runQuick("sh", "-c", "command -v add-apt-repository"); err != nil {
		if output, err := apt(longTimeout, "apt-get", "install", "-y", "--no-install-recommends", "software-properties-common"); err != nil {
			return nil, fmt.Errorf("install repository tooling: %s", tail(string(output), 800))
		}
	}

	if output, err := runLong("add-apt-repository", "-y", "--no-update", reference); err != nil {
		return nil, fmt.Errorf("add repository: %s", tail(string(output), 800))
	}
	if output, err := apt(longTimeout, "apt-get", "update"); err != nil {
		// Leaving a broken repository behind would break every later install,
		// so undo it rather than leaving the server in that state.
		_, _ = runLong("add-apt-repository", "-y", "--remove", reference)
		_, _ = apt(longTimeout, "apt-get", "update")
		return nil, fmt.Errorf("the repository was added but apt could not read it, so it was removed again: %s", tail(string(output), 600))
	}

	invalidateUpdateCache()
	invalidateCandidateCache()
	_ = writeAudit("source.ppa.added", true, reference)
	return listPackageSources()
}

// removePPA unregisters a Launchpad PPA.
func removePPA(reference string) ([]packageSource, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("removing a repository requires root")
	}
	reference = strings.TrimSpace(reference)
	if !ppaPattern.MatchString(reference) {
		return nil, fmt.Errorf("%q is not a valid PPA reference", reference)
	}
	if output, err := runLong("add-apt-repository", "-y", "--remove", reference); err != nil {
		return nil, fmt.Errorf("remove repository: %s", tail(string(output), 800))
	}
	_, _ = apt(longTimeout, "apt-get", "update")

	invalidateUpdateCache()
	invalidateCandidateCache()
	_ = writeAudit("source.ppa.removed", true, reference)
	return listPackageSources()
}

// disablePackageSource turns off a curated repository by commenting out its
// entries, which is reversible and leaves the signing key in place.
//
// Packages already installed from the repository are left alone: removing them
// is a separate, destructive decision the user should make explicitly.
func disablePackageSource(id string) ([]sourceCatalogItem, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("source-disable must run as root")
	}

	fragment, ok := curatedSourceURIFragments[id]
	if !ok {
		return nil, fmt.Errorf("unknown repository %q", id)
	}

	paths, _ := filepath.Glob("/etc/apt/sources.list.d/*")
	paths = append(paths, "/etc/apt/sources.list")
	changed := false

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		if !strings.HasSuffix(path, ".list") && !strings.HasSuffix(path, ".sources") && path != "/etc/apt/sources.list" {
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		lines := strings.Split(string(contents), "\n")
		fileChanged := false
		for index, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(line, fragment) {
				lines[index] = "# " + line + "  " + managedSourceMarker + " (disabled)"
				fileChanged = true
			}
		}
		if fileChanged {
			if err := atomicWrite(path, []byte(strings.Join(lines, "\n")), 0644); err != nil {
				return nil, fmt.Errorf("update %s: %w", path, err)
			}
			changed = true
		}
	}

	if !changed {
		return packageSourceCatalog()
	}

	if output, err := apt(longTimeout, "apt-get", "update"); err != nil {
		return nil, fmt.Errorf("refresh package information: %s", tail(string(output), 600))
	}
	invalidateUpdateCache()
	invalidateCandidateCache()
	_ = writeAudit("source.disabled", true, id)
	return packageSourceCatalog()
}

// curatedSourceURIFragments maps a catalogue entry to the URI substring that
// identifies its lines in the apt configuration.
var curatedSourceURIFragments = map[string]string{
	"docker": "download.docker.com/linux/ubuntu",
}

// repositoryPublishesSuite reports whether a repository actually carries packages
// for a given Ubuntu release.
//
// Availability was previously guessed: first from a list of releases known to
// work, which refused every release published after the code was written, then
// from a list known to be finished, which let the user enable a repository that
// turned out to have nothing for them and surfaced apt's raw 404.
//
// Asking the repository is the only answer that stays correct on its own. Every
// apt repository publishes dists/<suite>/Release, so its presence is the same
// question apt itself asks, one request earlier and with a sentence the user can
// act on.
func repositoryPublishesSuite(baseURL, codename string) bool {
	url := strings.TrimSuffix(baseURL, "/") + "/dists/" + codename + "/Release"
	// Short: this runs while someone waits on a button, and a repository that
	// cannot answer quickly is not one to add.
	output, err := runWithTimeout(quickTimeout, "curl", "--silent", "--head", "--fail",
		"--location", "--max-time", "10", "--output", "/dev/null",
		"--write-out", "%{http_code}", url)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "200"
}

// curatedSourceBaseURLs is where each curated repository publishes its suites.
var curatedSourceBaseURLs = map[string]string{
	"docker": "https://download.docker.com/linux/ubuntu",
}
