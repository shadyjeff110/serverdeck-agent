package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// One backup format, two scopes.
//
// Backups used to be two unrelated things: a whole-server archive that could
// only be restored over the top of the same paths on the same machine, and a
// per-site export that was portable but invisible to the backup page. A user had
// no single place to see what they had, and no way to pull one site out of a
// server backup — which is the thing people actually need when one site breaks.
//
// A v2 backup is a bundle of per-site archives plus, for a server backup, the
// server's own configuration:
//
//	manifest.json          scope, contents, sizes, per-site index
//	sites/<domain>.sdsite  a complete site archive, byte-identical to a
//	                       standalone export, so one restore path serves both
//	server/                /var/lib/serverdeck and the web server config
//
// Because each site is a self-contained archive, restoring one site out of a
// full server backup is the same operation as importing a single-site export.

const backupFormatV2 = 2

type backupScope string

const (
	backupScopeServer backupScope = "server"
	backupScopeSite   backupScope = "site"
)

// backupManifest is the sidecar written next to each archive, so listing does
// not have to open and decompress every backup on the disk.
type backupManifest struct {
	ID        string      `json:"id"`
	Format    int         `json:"format"`
	Scope     backupScope `json:"scope"`
	CreatedAt string      `json:"created_at"`
	Archive   string      `json:"archive"`
	Size      int64       `json:"size"`
	SHA256    string      `json:"sha256"`

	Sites     []string `json:"sites"`
	Databases []string `json:"databases"`

	// What a site-scoped backup actually contains, so a partial one can say so
	// rather than looking like a complete backup that fails on restore.
	IncludesFiles     bool `json:"includes_files"`
	IncludesDatabases bool `json:"includes_databases"`

	AgentVersion string `json:"agent_version,omitempty"`
	Verified     bool   `json:"verified"`
}

const backupRoot = "/var/backups/serverdeck"

// MARK: - Creation

// createServerBackup archives every managed site plus the server configuration.
func createServerBackup() (backupManifest, error) {
	return createBackupOfScope(backupScopeServer, nil, true, true)
}

// createSiteBackup archives a single site.
//
// Both contents default to true at every caller. A backup missing one of them
// cannot restore the site on its own, so the choice exists but the manifest
// records it and the interface warns.
func createSiteBackup(domain string, includeFiles, includeDatabases bool) (backupManifest, error) {
	if !includeFiles && !includeDatabases {
		return backupManifest{}, errors.New("a backup must include the files, the database, or both")
	}
	return createBackupOfScope(backupScopeSite, []string{normaliseHost(domain)}, includeFiles, includeDatabases)
}

func createBackupOfScope(scope backupScope, only []string, includeFiles, includeDatabases bool) (backupManifest, error) {
	manifest := backupManifest{}
	if os.Geteuid() != 0 {
		return manifest, errors.New("creating a backup requires root")
	}

	// Reclaim anything a previous run left behind before asking for more disk.
	sweepQuietly()

	sites, err := listSites()
	if err != nil {
		return manifest, err
	}
	if len(only) > 0 {
		filtered := make([]site, 0, len(only))
		for _, candidate := range sites {
			for _, wanted := range only {
				if candidate.Domain == wanted {
					filtered = append(filtered, candidate)
				}
			}
		}
		if len(filtered) == 0 {
			return manifest, fmt.Errorf("%s is not a site ServerDeck manages", strings.Join(only, ", "))
		}
		sites = filtered
	}

	// Sum what the archive will hold before committing to building it.
	var needed int64
	for _, value := range sites {
		if includeFiles {
			needed += directorySize(value.Root)
		}
		if includeDatabases {
			if database, _, ok := siteDatabase(value.Domain); ok {
				needed += databaseSize(database)
			}
		}
	}
	if err := ensureRoomFor(backupRoot, needed); err != nil {
		return manifest, err
	}

	id := backupID(scope, only)
	root := filepath.Join(backupRoot, id)
	if err := os.MkdirAll(filepath.Join(root, "staging", "sites"), 0700); err != nil {
		return manifest, err
	}
	staging := filepath.Join(root, "staging")
	defer os.RemoveAll(staging)

	manifest = backupManifest{
		ID:                id,
		Format:            backupFormatV2,
		Scope:             scope,
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
		AgentVersion:      version,
		IncludesFiles:     includeFiles,
		IncludesDatabases: includeDatabases,
		Sites:             []string{},
		Databases:         []string{},
	}

	for _, value := range sites {
		emitProgress("sites", "running", "Archiving "+value.Domain)
		archivePath := filepath.Join(staging, "sites", value.Domain+siteExportSuffix)
		siteManifest, err := writeSiteArchive(value, archivePath, includeFiles, includeDatabases)
		if err != nil {
			return manifest, fmt.Errorf("archive %s: %w", value.Domain, err)
		}
		manifest.Sites = append(manifest.Sites, value.Domain)
		if siteManifest.Database != "" {
			manifest.Databases = append(manifest.Databases, siteManifest.Database)
		}
	}

	if scope == backupScopeServer {
		emitProgress("server", "running", "Archiving server configuration")
		if err := writeServerConfig(filepath.Join(staging, "server")); err != nil {
			return manifest, err
		}
	}

	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return manifest, err
	}
	if err := atomicWrite(filepath.Join(staging, "manifest.json"), append(encoded, '\n'), 0600); err != nil {
		return manifest, err
	}

	emitProgress("archive", "running", "Compressing the backup")
	archivePath := filepath.Join(root, "backup"+siteExportSuffix)
	if output, err := runWithTimeout(longTimeout, "sh", "-c", gentleArchiveCommand(archivePath, staging)); err != nil {
		_ = os.RemoveAll(root)
		return manifest, fmt.Errorf("create archive: %s", tail(string(output), 400))
	}
	_ = os.Chmod(archivePath, 0600)

	info, err := os.Stat(archivePath)
	if err != nil {
		return manifest, err
	}
	sum, err := fileSHA256(archivePath)
	if err != nil {
		return manifest, err
	}
	manifest.Archive, manifest.Size, manifest.SHA256, manifest.Verified = archivePath, info.Size(), sum, true

	// The sidecar is what listing reads, so it is written last: a backup that
	// failed partway leaves no manifest and is therefore never offered.
	encoded, _ = json.MarshalIndent(manifest, "", "  ")
	if err := atomicWrite(filepath.Join(root, "manifest.json"), append(encoded, '\n'), 0600); err != nil {
		return manifest, err
	}

	_ = writeAudit("backup.created", true, string(scope)+" "+id)
	emitProgress("done", "succeeded", "Backup complete")
	return manifest, nil
}

func backupID(scope backupScope, only []string) string {
	stamp := time.Now().UTC().Format("20060102-150405")
	if scope == backupScopeSite && len(only) == 1 {
		return fmt.Sprintf("site-%s-%s", only[0], stamp)
	}
	return "server-" + stamp
}

// writeServerConfig captures the state needed to rebuild the server itself,
// separate from the sites it hosts.
func writeServerConfig(destination string) error {
	if err := os.MkdirAll(destination, 0700); err != nil {
		return err
	}
	for _, source := range []string{
		"/var/lib/serverdeck/sites",
		"/var/lib/serverdeck/apps",
		"/var/lib/serverdeck/databases",
		"/var/lib/serverdeck/staging",
		"/etc/nginx/sites-available",
		"/etc/apache2/sites-available",
	} {
		if _, err := os.Stat(source); err != nil {
			continue
		}
		target := filepath.Join(destination, strings.ReplaceAll(strings.TrimPrefix(source, "/"), "/", "_"))
		if output, err := runWithTimeout(longTimeout, "cp", "-a", source, target); err != nil {
			return fmt.Errorf("copy %s: %s", source, tail(string(output), 200))
		}
	}
	return nil
}

// MARK: - Listing

// listAllBackups reports every backup on the server.
func listAllBackups() ([]backupManifest, error) {
	paths, err := filepath.Glob(filepath.Join(backupRoot, "*", "manifest.json"))
	if err != nil {
		return nil, err
	}

	values := make([]backupManifest, 0, len(paths))
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var manifest backupManifest
		if json.Unmarshal(contents, &manifest) != nil {
			continue
		}
		if manifest.ID == "" {
			manifest.ID = filepath.Base(filepath.Dir(path))
		}

		// A directory without a current manifest is unfinished work, not a
		// backup, and the sweep will collect it.
		if manifest.Format < backupFormatV2 {
			continue
		}

		if manifest.Archive != "" {
			if sum, err := fileSHA256(manifest.Archive); err == nil {
				manifest.Verified = sum == manifest.SHA256
			} else {
				manifest.Verified = false
			}
		}
		values = append(values, manifest)
	}

	sort.Slice(values, func(i, j int) bool { return values[i].CreatedAt > values[j].CreatedAt })
	return values, nil
}

func readBackupManifest(id string) (backupManifest, error) {
	if err := validBackupID(id); err != nil {
		return backupManifest{}, err
	}
	all, err := listAllBackups()
	if err != nil {
		return backupManifest{}, err
	}
	for _, manifest := range all {
		if manifest.ID == id {
			return manifest, nil
		}
	}
	return backupManifest{}, fmt.Errorf("backup %s was not found", id)
}

// validBackupID keeps an id from reaching outside the backup directory.
func validBackupID(id string) error {
	if id == "" || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return errors.New("invalid backup id")
	}
	return nil
}

// MARK: - Deletion

func deleteBackup(id string) ([]backupManifest, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("deleting a backup requires root")
	}
	if err := validBackupID(id); err != nil {
		return nil, err
	}
	if _, err := readBackupManifest(id); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(filepath.Join(backupRoot, id)); err != nil {
		return nil, err
	}
	_ = writeAudit("backup.deleted", true, id)
	return listAllBackups()
}

// MARK: - Restore

// restoreSiteFromBackup pulls one site out of any v2 backup, optionally landing
// it on a different domain.
//
// This is the same operation as importing a standalone export, because the site
// archive inside a backup is the same format.
func restoreSiteFromBackup(id, sourceDomain, targetDomain string) (cloneResult, error) {
	result := cloneResult{}
	if os.Geteuid() != 0 {
		return result, errors.New("restoring requires root")
	}

	manifest, err := readBackupManifest(id)
	if err != nil {
		return result, err
	}
	if !manifest.IncludesFiles && !manifest.IncludesDatabases {
		return result, errors.New("this backup contains nothing to restore")
	}

	sourceDomain = normaliseHost(sourceDomain)
	if targetDomain == "" {
		targetDomain = sourceDomain
	}
	targetDomain = normaliseHost(targetDomain)

	staging, err := os.MkdirTemp(backupRoot, ".restore-*")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(staging)

	emitProgress("extract", "running", "Reading the backup")
	member := "./sites/" + sourceDomain + siteExportSuffix
	if output, err := runWithTimeout(longTimeout, "tar", "-xzf", manifest.Archive, "-C", staging, member); err != nil {
		return result, fmt.Errorf("%s is not in this backup: %s", sourceDomain, tail(string(output), 200))
	}

	// Hand the extracted site archive to the import path, which already knows
	// how to repoint wp-config and rewrite URLs onto a new domain.
	session := strings.ReplaceAll(id+sourceDomain, ".", "")
	if output, err := runWithTimeout(longTimeout, "cp",
		filepath.Join(staging, "sites", sourceDomain+siteExportSuffix), uploadedImportPath(session)); err != nil {
		return result, fmt.Errorf("stage restore: %s", tail(string(output), 200))
	}
	defer os.Remove(uploadedImportPath(session))

	return importSite(session, targetDomain)
}

// restoreBackupV2 restores every site in a backup.
func restoreBackupV2(id string) ([]string, error) {
	manifest, err := readBackupManifest(id)
	if err != nil {
		return nil, err
	}
	restored := []string{}
	for _, domain := range manifest.Sites {
		emitProgress("restore", "running", "Restoring "+domain)
		// An existing site is replaced by removing it first; the alternative is
		// refusing the whole restore because one site is present, which is the
		// opposite of what someone reaching for a backup wants.
		if _, err := readSiteMetadata(domain); err == nil {
			if err := deleteSite(domain, true); err != nil {
				return restored, fmt.Errorf("replace %s: %w", domain, err)
			}
		}
		if _, err := restoreSiteFromBackup(id, domain, domain); err != nil {
			return restored, fmt.Errorf("restore %s: %w", domain, err)
		}
		restored = append(restored, domain)
	}

	_ = writeAudit("backup.restored", true, id)
	emitProgress("done", "succeeded", fmt.Sprintf("Restored %d site(s)", len(restored)))
	return restored, nil
}

// pruneBackupsToRetention keeps the newest N backups and deletes the rest.
//
// Server backups only: a per-site backup is made deliberately for a particular
// reason, and silently deleting one because a nightly schedule produced newer
// ones would remove the thing the user was relying on.
func pruneBackupsToRetention(retention int) ([]string, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("pruning backups requires root")
	}
	if retention < 1 {
		retention = 1
	}

	all, err := listAllBackups()
	if err != nil {
		return nil, err
	}
	scheduled := []backupManifest{}
	for _, manifest := range all {
		if manifest.Scope == backupScopeServer {
			scheduled = append(scheduled, manifest)
		}
	}
	// listAllBackups sorts newest first.
	removed := []string{}
	for index := retention; index < len(scheduled); index++ {
		if os.RemoveAll(filepath.Join(backupRoot, scheduled[index].ID)) == nil {
			removed = append(removed, scheduled[index].ID)
		}
	}
	if len(removed) > 0 {
		_ = writeAudit("backup.pruned", true, fmt.Sprintf("%d removed", len(removed)))
	}
	return removed, nil
}
