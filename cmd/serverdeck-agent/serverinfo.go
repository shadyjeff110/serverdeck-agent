package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Server-level settings the app exposes on its Settings page.
//
// Both of these are one-line shell commands, but doing them by hand means
// opening a terminal — which is the thing this app exists to avoid.

type serverIdentity struct {
	Hostname     string   `json:"hostname"`
	PrettyName   string   `json:"pretty_name,omitempty"`
	Timezone     string   `json:"timezone"`
	LocalTime    string   `json:"local_time,omitempty"`
	NTPActive    bool     `json:"ntp_active"`
	SwapTotalMB  int64    `json:"swap_total_mb"`
	MemoryMB     int64    `json:"memory_mb"`
	Warnings     []string `json:"warnings,omitempty"`
	CanSetSwap   bool     `json:"can_set_swap"`
	RebootNeeded bool     `json:"reboot_needed"`
}

// hostnamePattern matches a single RFC 1123 label or a dotted host name.
var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func readServerIdentity() (serverIdentity, error) {
	value := serverIdentity{}

	if output, err := runQuick("hostnamectl", "--static"); err == nil {
		value.Hostname = strings.TrimSpace(string(output))
	} else if output, err := runQuick("hostname"); err == nil {
		value.Hostname = strings.TrimSpace(string(output))
	}

	if output, err := runQuick("timedatectl", "show", "--property=Timezone", "--value"); err == nil {
		value.Timezone = strings.TrimSpace(string(output))
	}
	if output, err := runQuick("timedatectl", "show", "--property=NTPSynchronized", "--value"); err == nil {
		value.NTPActive = strings.TrimSpace(string(output)) == "yes"
	}
	if output, err := runQuick("date", "+%Y-%m-%d %H:%M:%S %Z"); err == nil {
		value.LocalTime = strings.TrimSpace(string(output))
	}

	value.MemoryMB = readMeminfoMB("MemTotal:")
	value.SwapTotalMB = readMeminfoMB("SwapTotal:")
	value.CanSetSwap = os.Geteuid() == 0

	// Surfaced because it is the difference between a memory spike being slow
	// and being fatal: without swap the kernel has nothing to fall back on, and
	// a small instance running a database has no margin at all.
	if value.SwapTotalMB == 0 {
		if value.MemoryMB > 0 && value.MemoryMB < 2048 {
			value.Warnings = append(value.Warnings,
				fmt.Sprintf("This server has %d MB of memory and no swap. A brief spike can take it offline rather than merely slowing it down.", value.MemoryMB))
		} else {
			value.Warnings = append(value.Warnings, "This server has no swap configured.")
		}
	}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		value.RebootNeeded = true
	}
	return value, nil
}

func readMeminfoMB(prefix string) int64 {
	contents, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(contents), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		var kilobytes int64
		if _, err := fmt.Sscanf(fields[1], "%d", &kilobytes); err != nil {
			return 0
		}
		return kilobytes / 1024
	}
	return 0
}

// setHostname changes the static host name.
//
// /etc/hosts is updated alongside it: a host name with no loopback entry makes
// sudo pause on every invocation while name resolution times out, which turns a
// cosmetic change into an apparently broken server.
func setHostname(hostname string) (serverIdentity, error) {
	if os.Geteuid() != 0 {
		return serverIdentity{}, errors.New("changing the host name requires root")
	}
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" || len(hostname) > 253 || !hostnamePattern.MatchString(hostname) {
		return serverIdentity{}, errors.New("that is not a valid host name")
	}

	previous, _ := runQuick("hostnamectl", "--static")
	if output, err := run("hostnamectl", "set-hostname", hostname); err != nil {
		return serverIdentity{}, fmt.Errorf("set host name: %s", tail(string(output), 400))
	}

	if err := ensureHostsEntry(hostname, strings.TrimSpace(string(previous))); err != nil {
		// Roll back rather than leave the server with a name it cannot resolve.
		if old := strings.TrimSpace(string(previous)); old != "" {
			_, _ = run("hostnamectl", "set-hostname", old)
		}
		return serverIdentity{}, err
	}

	_ = writeAudit("server.hostname.changed", true, hostname)
	return readServerIdentity()
}

// ensureHostsEntry points 127.0.1.1 at the new name, replacing the old one.
func ensureHostsEntry(hostname, previous string) error {
	const path = "/etc/hosts"
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	lines := strings.Split(string(contents), "\n")
	replaced := false
	for index, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "127.0.1.1" {
			lines[index] = "127.0.1.1\t" + hostname
			replaced = true
			continue
		}
		// Drop the previous name from the loopback line if it was listed there.
		if previous != "" && len(fields) >= 2 && fields[0] == "127.0.0.1" {
			kept := fields[:1]
			for _, field := range fields[1:] {
				if field != previous {
					kept = append(kept, field)
				}
			}
			lines[index] = strings.Join(kept, "\t")
		}
	}
	if !replaced {
		lines = append(lines, "127.0.1.1\t"+hostname)
	}

	return atomicWrite(path, []byte(strings.Join(lines, "\n")), 0644)
}

func setTimezone(zone string) (serverIdentity, error) {
	if os.Geteuid() != 0 {
		return serverIdentity{}, errors.New("changing the time zone requires root")
	}
	zone = strings.TrimSpace(zone)
	// Validated against the system's own list rather than a pattern, so an
	// unknown zone is rejected before timedatectl is asked to apply it.
	if output, err := runQuick("timedatectl", "list-timezones"); err == nil {
		found := false
		for _, candidate := range strings.Split(string(output), "\n") {
			if strings.TrimSpace(candidate) == zone {
				found = true
				break
			}
		}
		if !found {
			return serverIdentity{}, fmt.Errorf("%q is not a time zone this server recognises", zone)
		}
	}
	if output, err := run("timedatectl", "set-timezone", zone); err != nil {
		return serverIdentity{}, fmt.Errorf("set time zone: %s", tail(string(output), 400))
	}
	_ = writeAudit("server.timezone.changed", true, zone)
	return readServerIdentity()
}

func listTimezones() ([]string, error) {
	output, err := runQuick("timedatectl", "list-timezones")
	if err != nil {
		return nil, fmt.Errorf("list time zones: %s", tail(string(output), 300))
	}
	zones := []string{}
	for _, line := range strings.Split(string(output), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			zones = append(zones, trimmed)
		}
	}
	return zones, nil
}
