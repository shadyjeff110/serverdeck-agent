package main

import (
	"strings"
)

// Batched package lookups.
//
// listSoftware walks a catalogue of roughly fifteen packages and previously
// asked apt and dpkg about each one individually. Both tools load their whole
// database per invocation, so that was ~15 apt-cache processes at about 70 MB
// peak between them — measured at 5.5s and 69 MB on a 1 GB instance, by far the
// most expensive thing in a refresh.
//
// Both accept many package names at once, so the same information costs one
// process instead of fifteen.

// packageCandidates returns the candidate version for each requested package.
// Packages with no installation candidate are absent from the map.
func packageCandidates(names []string) map[string]string {
	candidates := map[string]string{}
	if len(names) == 0 {
		return candidates
	}

	output, err := runOutputWithTimeout(defaultTimeout, "apt-cache", append([]string{"policy"}, names...)...)
	if err != nil {
		return candidates
	}

	// `apt-cache policy a b c` emits a stanza per package:
	//
	//   nginx:
	//     Installed: 1.18.0-0ubuntu1
	//     Candidate: 1.18.0-0ubuntu1
	//
	// Package headers sit at column zero; their fields are indented.
	current := ""
	for _, raw := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(raw, " ") && strings.HasSuffix(trimmed, ":") {
			current = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if current != "" && strings.HasPrefix(trimmed, "Candidate:") {
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "Candidate:"))
			if value != "(none)" {
				candidates[current] = value
			}
			current = ""
		}
	}
	return candidates
}

// packageVersions returns the installed version for each requested package.
// Packages that are not installed are absent from the map.
func packageVersions(names []string) map[string]string {
	versions := map[string]string{}
	if len(names) == 0 {
		return versions
	}

	// dpkg-query exits non-zero when any name is unknown, but still reports the
	// ones it does know, so the output is parsed regardless of exit status.
	args := append([]string{"-W", "-f=${Package}\t${Status}\t${Version}\n"}, names...)
	output, _ := runOutputWithTimeout(defaultTimeout, "dpkg-query", args...)

	for _, line := range strings.Split(string(output), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "\t", 3)
		if len(parts) != 3 {
			continue
		}
		if strings.HasPrefix(parts[1], "install ok installed") {
			versions[parts[0]] = parts[2]
		}
	}
	return versions
}
