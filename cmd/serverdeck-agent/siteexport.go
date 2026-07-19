package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Portable per-site archives.
//
// This is not the same thing as the whole-server backup next door. That one tars
// every site, every database and the web server configuration, and restores them
// over the top of the same paths on the same machine — it is disaster recovery,
// and it cannot move one site somewhere else or land it on a different domain.
//
// A .sdsite archive is the opposite: one site, self-describing, and restorable on
// a different server under a different name. It exists so leaving a server is not
// a reason to stay on it.
//
// Layout:
//
//	manifest.json   what this is, where it came from, and what it should contain
//	files/          the document root, verbatim
//	database.sql    omitted entirely for a site with no database
//	vhost.conf      the source web server config, kept for reference only
//
// The manifest is versioned so that an importer meeting a newer archive refuses
// it outright. Half-restoring a site because an unknown field was ignored is far
// worse than declining to start.

const (
	siteExportFormat  = 1
	siteExportDir     = "/var/lib/serverdeck/exports"
	siteExportSuffix  = ".sdsite"
	siteImportTempDir = "/var/lib/serverdeck/imports"
)

type siteExportManifest struct {
	Format       int    `json:"format"`
	CreatedAt    string `json:"created_at"`
	AgentVersion string `json:"agent_version"`

	SourceDomain   string `json:"source_domain"`
	SourceHostname string `json:"source_hostname,omitempty"`
	Kind           string `json:"kind"`
	PHPVersion     string `json:"php_version,omitempty"`
	WebServer      string `json:"web_server,omitempty"`

	IsWordPress  bool   `json:"is_wordpress"`
	Database     string `json:"database,omitempty"`
	DatabaseUser string `json:"database_user,omitempty"`

	FilesBytes    int64 `json:"files_bytes"`
	DatabaseBytes int64 `json:"database_bytes"`

	// Stated in the archive itself, not only in the interface that produced it,
	// because the file outlives the screen that warned about it.
	ContainsCredentials bool   `json:"contains_credentials"`
	CredentialsNotice   string `json:"credentials_notice,omitempty"`
}

type siteExport struct {
	ID       string             `json:"id"`
	Domain   string             `json:"domain"`
	Path     string             `json:"path"`
	Size     int64              `json:"size"`
	SHA256   string             `json:"sha256"`
	Manifest siteExportManifest `json:"manifest"`
}

const credentialsNotice = "This archive contains the site's files exactly as they were, including any configuration file holding database credentials. Treat it like a password."

// exportSite builds a standalone archive of one site.
func exportSite(domain string) (siteExport, error) {
	if os.Geteuid() != 0 {
		return siteExport{}, errors.New("site-export must run as root")
	}
	domain = normaliseHost(domain)

	value, err := readSiteMetadata(domain)
	if err != nil {
		return siteExport{}, fmt.Errorf("%s is not a site ServerDeck manages", domain)
	}
	sweepQuietly()
	if err := os.MkdirAll(siteExportDir, 0700); err != nil {
		return siteExport{}, err
	}
	// Refuse before starting rather than partway: a full disk takes out every
	// site on the server, not only the one being exported.
	needed := directorySize(value.Root)
	if database, _, ok := siteDatabase(domain); ok {
		needed += databaseSize(database)
	}
	if err := ensureRoomFor(siteExportDir, needed); err != nil {
		return siteExport{}, err
	}

	id := fmt.Sprintf("%s-%s", domain, time.Now().UTC().Format("20060102-150405"))
	archivePath := filepath.Join(siteExportDir, id+siteExportSuffix)

	manifest, err := writeSiteArchive(value, archivePath, true, true)
	if err != nil {
		return siteExport{}, err
	}

	info, err := os.Stat(archivePath)
	if err != nil {
		return siteExport{}, err
	}
	sum, err := fileSHA256(archivePath)
	if err != nil {
		return siteExport{}, err
	}

	_ = writeAudit("site.exported", true, domain)
	emitProgress("done", "succeeded", "Export ready")
	return siteExport{ID: id, Domain: domain, Path: archivePath, Size: info.Size(), SHA256: sum, Manifest: manifest}, nil
}

// writeSiteArchive builds one .sdsite at the given path.
//
// Shared by standalone exports and by backups, so a site pulled out of a server
// backup restores through exactly the same code as an uploaded export. The
// include flags exist for partial backups; both are true everywhere else.
func writeSiteArchive(value site, archivePath string, includeFiles, includeDatabases bool) (siteExportManifest, error) {
	domain := normaliseHost(value.Domain)

	staging, err := os.MkdirTemp(filepath.Dir(archivePath), ".archive-*")
	if err != nil {
		return siteExportManifest{}, err
	}
	defer os.RemoveAll(staging)

	manifest := siteExportManifest{
		Format:              siteExportFormat,
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
		AgentVersion:        version,
		SourceDomain:        domain,
		Kind:                value.Kind,
		PHPVersion:          value.PHPVersion,
		WebServer:           value.WebServer,
		ContainsCredentials: includeFiles,
	}
	if includeFiles {
		manifest.CredentialsNotice = credentialsNotice
	}
	if hostname, err := runQuick("hostname"); err == nil {
		manifest.SourceHostname = strings.TrimSpace(string(hostname))
	}

	if includeFiles {
		emitProgress("files", "running", "Collecting files for "+domain)
		// Hard links rather than copies: the archive is read-only input to tar,
		// and on a small server duplicating a document root purely to compress
		// it can be the difference between a backup working and filling the disk.
		filesDir := filepath.Join(staging, "files")
		if _, err := runWithTimeout(longTimeout, "cp", "-al", value.Root, filesDir); err != nil {
			if output, copyErr := runWithTimeout(longTimeout, "cp", "-a", value.Root, filesDir); copyErr != nil {
				return manifest, fmt.Errorf("collect files: %s", tail(string(output), 400))
			}
		}
		manifest.FilesBytes = directorySize(value.Root)
	}

	// Any site with a database, not only WordPress. Gating this on WordPress
	// meant a Drupal or Joomla site was archived as files only, which cannot
	// restore it — and nothing said so.
	if includeDatabases {
		if database, user, ok := siteDatabase(domain); ok {
			manifest.Database = database
			manifest.DatabaseUser = user
			// Only WordPress gets its URLs rewritten on restore; for anything
			// else the database is restored as-is.
			manifest.IsWordPress = isWordPressApp(domain)

			emitProgress("database", "running", "Exporting the database for "+domain)
			dumpPath := filepath.Join(staging, "database.sql")
			if err := dumpDatabase(database, dumpPath); err != nil {
				return manifest, err
			}
			if info, err := os.Stat(dumpPath); err == nil {
				manifest.DatabaseBytes = info.Size()
			}
		}
	}

	// Reference only. It cannot be applied verbatim on another server, whose
	// paths and PHP socket differ, but a site with hand-tuned redirects or
	// caching rules would otherwise lose them silently.
	if configPath := vhostPathFor(domain, value.WebServer); configPath != "" {
		if contents, err := os.ReadFile(configPath); err == nil {
			_ = atomicWrite(filepath.Join(staging, "vhost.conf"), contents, 0600)
		}
	}

	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return manifest, err
	}
	if err := atomicWrite(filepath.Join(staging, "manifest.json"), append(encoded, '\n'), 0600); err != nil {
		return manifest, err
	}

	emitProgress("archive", "running", "Compressing "+domain)
	if output, err := runWithTimeout(longTimeout, "sh", "-c", gentleArchiveCommand(archivePath, staging)); err != nil {
		_ = os.Remove(archivePath)
		return manifest, fmt.Errorf("create archive: %s", tail(string(output), 400))
	}
	_ = os.Chmod(archivePath, 0600)
	return manifest, nil
}

func listSiteExports() ([]siteExport, error) {
	exports := []siteExport{}
	entries, err := os.ReadDir(siteExportDir)
	if err != nil {
		return exports, nil
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), siteExportSuffix) {
			continue
		}
		path := filepath.Join(siteExportDir, entry.Name())
		info, err := entry.Info()
		if err != nil {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), siteExportSuffix)
		export := siteExport{ID: id, Path: path, Size: info.Size()}
		if manifest, err := readArchiveManifest(path); err == nil {
			export.Manifest = manifest
			export.Domain = manifest.SourceDomain
		}
		exports = append(exports, export)
	}
	return exports, nil
}

func deleteSiteExport(id string) error {
	// Constrained to the export directory so an id can never reach elsewhere.
	if id == "" || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return errors.New("invalid export id")
	}
	return os.Remove(filepath.Join(siteExportDir, id+siteExportSuffix))
}

// MARK: - Import

type siteImportPlan struct {
	Manifest     siteExportManifest `json:"manifest"`
	Allowed      bool               `json:"allowed"`
	Reason       string             `json:"reason,omitempty"`
	SuggestedTLD string             `json:"suggested_domain,omitempty"`
	Warnings     []string           `json:"warnings,omitempty"`
}

// planSiteImport validates an uploaded archive without changing anything.
func planSiteImport(session, targetDomain string) (siteImportPlan, error) {
	plan := siteImportPlan{}
	archivePath := uploadedImportPath(session)

	if _, err := os.Stat(archivePath); err != nil {
		return plan, errors.New("the uploaded archive could not be found; the upload may not have finished")
	}

	archiveStats, err := inspectSiteArchive(archivePath)
	if err != nil {
		plan.Reason = err.Error()
		return plan, nil
	}
	manifest := archiveStats.Manifest
	plan.Manifest = manifest
	plan.SuggestedTLD = manifest.SourceDomain

	// Refuse rather than guess. A newer archive may carry fields whose absence
	// changes what a correct restore looks like.
	if manifest.Format > siteExportFormat {
		plan.Reason = fmt.Sprintf("This archive was made by a newer version of ServerDeck (format %d). Update the agent on this server before importing it.", manifest.Format)
		return plan, nil
	}
	if manifest.Format < 1 {
		plan.Reason = "This file does not look like a ServerDeck site archive."
		return plan, nil
	}

	targetDomain = normaliseHost(targetDomain)
	if targetDomain == "" {
		targetDomain = manifest.SourceDomain
	}
	if !domainPattern.MatchString(targetDomain) {
		plan.Reason = "The destination domain is not a valid host name"
		return plan, nil
	}
	if _, err := readSiteMetadata(targetDomain); err == nil {
		plan.Reason = fmt.Sprintf("%s already exists on this server", targetDomain)
		return plan, nil
	}

	if manifest.IsWordPress && targetDomain != manifest.SourceDomain {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("Site URLs will be rewritten from %s to %s.", manifest.SourceDomain, targetDomain))
	}
	if !manifest.IsWordPress && manifest.Kind == "php" {
		plan.Warnings = append(plan.Warnings,
			"This is a PHP site that is not WordPress. Files are restored as-is, so any database settings written into its code must be updated by hand.")
	}
	if manifest.PHPVersion != "" && packageVersion("php"+manifest.PHPVersion+"-fpm") == "" {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("The source ran PHP %s, which is not installed here. The site will use the version this server provides.", manifest.PHPVersion))
	}

	plan.Allowed = true
	return plan, nil
}

// importSite restores an uploaded archive as a site on this server.
func importSite(session, targetDomain string) (cloneResult, error) {
	result := cloneResult{}
	if os.Geteuid() != 0 {
		return result, errors.New("site-import must run as root")
	}

	plan, err := planSiteImport(session, targetDomain)
	if err != nil {
		return result, err
	}
	if !plan.Allowed {
		return result, errors.New(plan.Reason)
	}
	manifest := plan.Manifest

	targetDomain = normaliseHost(targetDomain)
	if targetDomain == "" {
		targetDomain = manifest.SourceDomain
	}

	sweepQuietly()
	if err := os.MkdirAll(siteImportTempDir, 0700); err != nil {
		return result, err
	}
	staging, err := os.MkdirTemp(siteImportTempDir, ".import-*")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(staging)

	emitProgress("extract", "running", "Reading the archive")
	if _, err := extractValidatedSiteArchive(uploadedImportPath(session), staging); err != nil {
		return result, fmt.Errorf("extract archive: %w", err)
	}

	created := []func(){}
	rollback := func() {
		for index := len(created) - 1; index >= 0; index-- {
			created[index]()
		}
	}

	emitProgress("site", "running", "Creating "+targetDomain)
	kind := manifest.Kind
	if kind != "php" && kind != "static" {
		kind = "static"
	}
	newSite, err := createSite(targetDomain, kind)
	if err != nil {
		return result, fmt.Errorf("create site: %w", err)
	}
	created = append(created, func() { _ = deleteSite(targetDomain, true) })

	emitProgress("files", "running", "Restoring website files")
	if err := copyTree(filepath.Join(staging, "files"), newSite.Root); err != nil {
		rollback()
		return result, fmt.Errorf("restore files: %w", err)
	}

	if manifest.Database != "" {
		dumpPath := filepath.Join(staging, "database.sql")
		if _, err := os.Stat(dumpPath); err != nil {
			rollback()
			return result, errors.New("the archive names a database but does not contain its contents")
		}

		emitProgress("database", "running", "Restoring the database")
		databaseName, user, password, err := createImportDatabase(targetDomain)
		if err != nil {
			rollback()
			return result, err
		}
		created = append(created, func() { _ = deleteDatabase(databaseName) })

		if err := restoreDatabaseDump(databaseName, dumpPath); err != nil {
			rollback()
			return result, err
		}

		if manifest.IsWordPress {
			emitProgress("config", "running", "Rewriting wp-config.php")
			if err := rewriteWPConfig(newSite.Root, databaseName, user, password); err != nil {
				rollback()
				return result, fmt.Errorf("update wp-config.php: %w", err)
			}
		} else {
			// A non-WordPress application keeps its own configuration file, whose
			// shape is unknown. The new credentials are reported rather than
			// written, because guessing at someone else's config is how a restore
			// quietly points at the wrong database.
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"The database was restored as %q. Update this site's configuration with the one-time credentials shown below.",
				databaseName))
			result.Database = &database{
				Name: databaseName, Username: user, Password: password, Host: "localhost",
				CreatedAt: time.Now().UTC().Format(time.RFC3339), Engine: databaseEngine(databaseName),
			}
		}

		if manifest.IsWordPress && targetDomain != manifest.SourceDomain {
			emitProgress("urls", "running", "Updating site URLs")
			if err := rewriteWordPressURLs(newSite.Root, manifest.SourceDomain, targetDomain); err != nil {
				rollback()
				return result, fmt.Errorf("update site URLs: %w", err)
			}
		}

		if record, ok := importedApplicationRecord(manifest, targetDomain, databaseName, user); ok {
			_ = writeInstalledApp(record)
		}
	}

	_ = os.Remove(uploadedImportPath(session))
	_ = writeAudit("site.imported", true, manifest.SourceDomain+" -> "+targetDomain)
	emitProgress("done", "succeeded", "Import complete")

	result.Site = newSite
	result.Warnings = mergeImportWarnings(plan.Warnings, result.Warnings)
	return result, nil
}

func mergeImportWarnings(planWarnings, runtimeWarnings []string) []string {
	merged := append([]string{}, planWarnings...)
	return append(merged, runtimeWarnings...)
}

func importedApplicationRecord(manifest siteExportManifest, domain, databaseName, user string) (installedApp, bool) {
	if !manifest.IsWordPress {
		return installedApp{}, false
	}
	return installedApp{
		App: "wordpress", Name: domain, Domain: domain,
		Database: databaseName, DatabaseUser: user,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
	}, true
}

// MARK: - Helpers

func uploadedImportPath(session string) string {
	// The session is generated by the app, but it still lands in a fixed
	// directory with no path separators permitted.
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, strings.ToLower(session))
	// Real disk, not /tmp: see uploadStagingDir for why.
	_ = os.MkdirAll(uploadStagingDir, 0700)
	return filepath.Join(uploadStagingDir, "siteimport-"+safe+siteExportSuffix)
}

// readArchiveManifest reads only the manifest, without unpacking the archive.
func readArchiveManifest(archivePath string) (siteExportManifest, error) {
	stats, err := inspectSiteArchive(archivePath)
	return stats.Manifest, err
}

func vhostPathFor(domain, webServer string) string {
	if webServer == "apache" {
		return filepath.Join("/etc/apache2/sites-available", domain+".conf")
	}
	return filepath.Join("/etc/nginx/sites-available", domain)
}

func dumpDatabase(name, destination string) error {
	dumper := "mariadb-dump"
	if _, err := runQuick("sh", "-c", "command -v mariadb-dump"); err != nil {
		dumper = "mysqldump"
	}
	script := fmt.Sprintf("set -o pipefail; %s --single-transaction --routines --triggers %s > %s",
		dumper, shellQuote(name), shellQuote(destination))
	if output, err := runWithTimeout(longTimeout, "bash", "-c", script); err != nil {
		return fmt.Errorf("export database: %s", tail(string(output), 400))
	}
	return nil
}

func restoreDatabaseDump(name, dumpPath string) error {
	client := "mariadb"
	if _, err := runQuick("sh", "-c", "command -v mariadb"); err != nil {
		client = "mysql"
	}
	script := fmt.Sprintf("set -o pipefail; %s %s < %s", client, shellQuote(name), shellQuote(dumpPath))
	if output, err := runWithTimeout(longTimeout, "bash", "-c", script); err != nil {
		return fmt.Errorf("restore database: %s", tail(string(output), 400))
	}
	return nil
}

// createImportDatabase makes a database for an imported site, returning the
// generated password, which createDatabase deliberately never persists.
func createImportDatabase(domain string) (name, user, password string, err error) {
	name = databaseNameForDomain(domain)
	user = name
	if len(user) > 32 {
		user = user[:32]
	}
	created, err := createDatabase(name, user)
	if err != nil {
		return "", "", "", fmt.Errorf("create database: %w", err)
	}
	if created.Password == "" {
		_ = deleteDatabase(name)
		return "", "", "", errors.New("the database was created without a password")
	}
	return name, user, created.Password, nil
}

// gentleArchiveCommand builds the tar invocation used for exports.
//
// Compressing a document root is the most expensive thing this agent does, and
// it runs on servers chosen for being small — the whole reason someone uses
// ServerDeck instead of a heavyweight panel. Two concessions make it survivable
// on a one-core box that is also serving traffic:
//
//   - gzip -1 rather than the default -6. A site is mostly images and archives
//     that are already compressed, so the size difference is small while the CPU
//     difference is large.
//   - nice and, where available, ionice, so the web server keeps priority. An
//     export that takes twice as long is a fine trade for one that does not make
//     the site unresponsive while it runs.
func gentleArchiveCommand(archivePath, staging string) string {
	prefix := "nice -n 19"
	// ionice is in util-linux on Debian and Ubuntu, but not guaranteed.
	if _, err := runQuick("sh", "-c", "command -v ionice"); err == nil {
		prefix += " ionice -c3"
	}
	return fmt.Sprintf("%s tar -I 'gzip -1' -cf %s -C %s .",
		prefix, shellQuote(archivePath), shellQuote(staging))
}
