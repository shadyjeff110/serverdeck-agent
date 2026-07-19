package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Removing work that never finished.
//
// Every long operation stages into a temporary directory and removes it with a
// deferred call. That covers a normal return and a panic, and nothing else: a
// process killed by the OOM killer, by a command deadline, or by the machine
// losing power never runs its deferred cleanup. On a small server, where being
// OOM-killed is the common failure rather than a rare one, that leaves whole
// document roots behind.
//
// Abandoned uploads are worse. The archive is deleted by the import that
// consumes it, so an upload the user walked away from — or one whose plan was
// rejected — is never deleted by anything. Those are the largest files the
// system handles.
//
// The sweep is age-based rather than tracking what is in flight. A running
// operation touches its staging directory continuously, so anything untouched
// for hours is finished or dead either way, and that holds without the agent
// having to remember state across a crash.

const (
	// Long enough that a genuinely slow operation on a slow machine is never
	// swept out from under itself.
	staleStagingAge = 6 * time.Hour
	// Uploads are kept longer: someone may upload in one sitting and import in
	// the next, and re-uploading gigabytes is an expensive mistake to force.
	staleUploadAge = 48 * time.Hour
)

type sweepResult struct {
	RemovedPaths []string `json:"removed_paths"`
	FreedBytes   int64    `json:"freed_bytes"`
	FreedHuman   string   `json:"freed_human"`
}

// sweepStaleWork removes staging directories and abandoned uploads.
func sweepStaleWork() (sweepResult, error) {
	result := sweepResult{RemovedPaths: []string{}}
	now := time.Now()

	// Staging directories, all of which are hidden and prefixed by their maker.
	for _, spec := range []struct {
		dir     string
		pattern string
	}{
		{siteExportDir, ".archive-*"},
		{siteImportTempDir, ".import-*"},
		{backupRoot, ".restore-*"},
		{"/var/lib/serverdeck", ".restore-*"},
		{"/var/lib/serverdeck", ".web-config-safety-*"},
	} {
		matches, _ := filepath.Glob(filepath.Join(spec.dir, spec.pattern))
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil || now.Sub(info.ModTime()) < staleStagingAge {
				continue
			}
			size := directorySize(path)
			if os.RemoveAll(path) == nil {
				result.RemovedPaths = append(result.RemovedPaths, path)
				result.FreedBytes += size
			}
		}
	}

	// A backup whose staging survived means the backup itself did not finish.
	// Its directory has no manifest, so it is invisible to the list and can only
	// waste space.
	if entries, err := os.ReadDir(backupRoot); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join(backupRoot, entry.Name())
			if _, err := os.Stat(filepath.Join(path, "manifest.json")); err == nil {
				continue // A real backup.
			}
			info, err := entry.Info()
			if err != nil || now.Sub(info.ModTime()) < staleStagingAge {
				continue
			}
			size := directorySize(path)
			if os.RemoveAll(path) == nil {
				result.RemovedPaths = append(result.RemovedPaths, path)
				result.FreedBytes += size
			}
		}
	}

	// Uploads waiting for an import that never came.
	for _, pattern := range []string{
		uploadStagingDir + "/import-*.wpress",
		uploadStagingDir + "/import-*.sql",
		uploadStagingDir + "/siteimport-*" + siteExportSuffix,
	} {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil || now.Sub(info.ModTime()) < staleUploadAge {
				continue
			}
			size := info.Size()
			if info.IsDir() {
				size = directorySize(path)
			}
			if os.RemoveAll(path) == nil {
				result.RemovedPaths = append(result.RemovedPaths, path)
				result.FreedBytes += size
			}
		}
	}

	result.FreedHuman = humanBytes(result.FreedBytes)
	if len(result.RemovedPaths) > 0 {
		_ = writeAudit("maintenance.swept", true,
			fmt.Sprintf("%d item(s), %s", len(result.RemovedPaths), result.FreedHuman))
	}
	return result, nil
}

// sweepQuietly runs a sweep before an operation that is about to need disk.
//
// Called at the start of the expensive operations rather than on a timer, so a
// server that is never asked to do anything is never woken up to tidy, and one
// that is gets tidied at exactly the moment the space matters. Failures are
// ignored: a sweep must never be the reason a backup does not start.
func sweepQuietly() {
	if os.Geteuid() != 0 {
		return
	}
	_, _ = sweepStaleWork()
}

// Choosing where large temporary work goes.
//
// /tmp looks like the obvious home for a transient upload, and it is the wrong
// one here. systemd's default is to mount /tmp as tmpfs, so on many systems it
// is RAM: staging a multi-gigabyte archive there consumes memory rather than
// disk and can take the machine down — the exact failure this software exists to
// avoid. Debian and Ubuntu also ship /tmp without an age rule, so the automatic
// cleanup one might be relying on may never run, and its 1777 permissions make
// it a poor place for archives holding database credentials.
//
// Work therefore goes on real disk under /var/lib/serverdeck, which is
// root-owned and which the sweep above clears deterministically.
const uploadStagingDir = "/var/lib/serverdeck/uploads"

// isTmpfs reports whether a path is backed by memory rather than disk.
func isTmpfs(path string) bool {
	output, err := runQuick("sh", "-c", fmt.Sprintf("df -PT %s 2>/dev/null | awk 'NR==2 {print $2}'", shellQuote(path)))
	if err != nil {
		return false
	}
	switch strings.TrimSpace(string(output)) {
	case "tmpfs", "ramfs":
		return true
	}
	return false
}

// freeBytes reports the space available on the filesystem holding a path.
func freeBytes(path string) int64 {
	var stat syscall.Statfs_t
	if syscall.Statfs(path, &stat) != nil {
		return 0
	}
	return int64(stat.Bavail) * int64(stat.Bsize)
}

// ensureRoomFor refuses an operation that would plainly not fit.
//
// Failing before starting is far kinder than failing partway: a full disk takes
// out every site on the server, not just the one being worked on.
func ensureRoomFor(path string, needed int64) error {
	available := freeBytes(path)
	if available == 0 || needed == 0 {
		return nil
	}
	// Headroom so a backup is never the thing that fills the disk.
	if available < needed+512*1024*1024 {
		return fmt.Errorf("not enough free disk space: this needs about %s and %s is available",
			humanBytes(needed), humanBytes(available))
	}
	return nil
}

// Installing the maintenance timer.
//
// The sweep also runs opportunistically before each expensive operation, which
// covers an active server. It does not cover the case that actually strands
// files: someone uploads an archive, abandons it, and never opens the app again.
// Nothing then triggers a sweep, and the largest files the system handles sit
// there indefinitely.
//
// A timer closes that. It is installed once and is cheap — a stat over a handful
// of directories, doing nothing at all on a tidy server.
func installMaintenanceTimer() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("installing the maintenance timer requires root")
	}

	service := "[Unit]\n" +
		"Description=ServerDeck maintenance sweep\n\n" +
		"[Service]\n" +
		"Type=oneshot\n" +
		// Deprioritised: tidying must never compete with the sites the server
		// exists to serve.
		"Nice=19\n" +
		"IOSchedulingClass=idle\n" +
		"ExecStart=/usr/local/bin/serverdeck-agent maintenance-sweep\n"

	timer := "[Unit]\n" +
		"Description=Daily ServerDeck maintenance sweep\n\n" +
		"[Timer]\n" +
		"OnCalendar=*-*-* 04:30:00\n" +
		// Runs after a machine that was off, rather than skipping silently.
		"Persistent=true\n" +
		"RandomizedDelaySec=30m\n" +
		"Unit=serverdeck-maintenance.service\n\n" +
		"[Install]\n" +
		"WantedBy=timers.target\n"

	if err := atomicWrite("/etc/systemd/system/serverdeck-maintenance.service", []byte(service), 0644); err != nil {
		return err
	}
	if err := atomicWrite("/etc/systemd/system/serverdeck-maintenance.timer", []byte(timer), 0644); err != nil {
		return err
	}
	if output, err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd: %s", tail(string(output), 300))
	}
	if output, err := run("systemctl", "enable", "--now", "serverdeck-maintenance.timer"); err != nil {
		return fmt.Errorf("enable the maintenance timer: %s", tail(string(output), 300))
	}
	_ = writeAudit("maintenance.timer.installed", true, "daily")
	return nil
}

// diskReport is what the app checks before starting a large upload.
type diskReport struct {
	UploadPath      string `json:"upload_path"`
	FreeBytes       int64  `json:"free_bytes"`
	FreeHuman       string `json:"free_human"`
	UploadIsMemory  bool   `json:"upload_is_memory"`
	BackupFreeBytes int64  `json:"backup_free_bytes"`
	BackupFreeHuman string `json:"backup_free_human"`
}

// reportDisk answers "will this fit" before the caller commits to sending it.
//
// Asking afterwards is the expensive order: a user waits out a multi-gigabyte
// upload only to be told at the end that the server was never going to have
// room, and the failure looks like a bug rather than arithmetic.
func reportDisk() (diskReport, error) {
	_ = os.MkdirAll(uploadStagingDir, 0700)
	_ = os.MkdirAll(backupRoot, 0700)
	report := diskReport{
		UploadPath:      uploadStagingDir,
		FreeBytes:       freeBytes(uploadStagingDir),
		UploadIsMemory:  isTmpfs(uploadStagingDir),
		BackupFreeBytes: freeBytes(backupRoot),
	}
	report.FreeHuman = humanBytes(report.FreeBytes)
	report.BackupFreeHuman = humanBytes(report.BackupFreeBytes)
	return report, nil
}
