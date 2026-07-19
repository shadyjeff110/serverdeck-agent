package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Website cloning and staging.
//
// A staging site is an ordinary managed site that additionally records where it
// was cloned from. Keeping it a real site means everything else — TLS, PHP
// version switching, file management, backups — works on it with no special
// cases; only the extra metadata and the safety hardening below are new.
//
// The direction is deliberately one-way. Cloning live to staging can only create
// something new, so a mistake costs a wasted clone. Pushing staging back over a
// live site is a genuinely destructive operation with an unsolved database merge
// problem (orders and comments arriving on live while staging is worked on), so
// it is not implemented here.

const stagingMetadataDir = "/var/lib/serverdeck/staging"

type stagingRecord struct {
	Domain       string `json:"domain"`
	SourceDomain string `json:"source_domain"`
	Kind         string `json:"kind"`
	Database     string `json:"database,omitempty"`
	DatabaseUser string `json:"database_user,omitempty"`
	IsWordPress  bool   `json:"is_wordpress"`
	CreatedAt    string `json:"created_at"`
	RefreshedAt  string `json:"refreshed_at,omitempty"`
}

// clonePlan is the preflight report shown before anything is changed.
type clonePlan struct {
	SourceDomain   string   `json:"source_domain"`
	TargetDomain   string   `json:"target_domain"`
	Allowed        bool     `json:"allowed"`
	Reason         string   `json:"reason,omitempty"`
	IsWordPress    bool     `json:"is_wordpress"`
	Kind           string   `json:"kind"`
	FilesBytes     int64    `json:"files_bytes"`
	DatabaseBytes  int64    `json:"database_bytes"`
	FreeBytes      int64    `json:"free_bytes"`
	SourceDatabase string   `json:"source_database,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

type cloneResult struct {
	Staging  stagingRecord `json:"staging"`
	Site     site          `json:"site"`
	Database *database     `json:"database,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
}

// planClone inspects both domains and reports whether the clone can proceed.
//
// Nothing is modified here: the app shows this to the user first, because a
// clone consumes real disk and creates a publicly reachable copy of a site.
func planClone(sourceDomain, targetDomain string) (clonePlan, error) {
	plan := clonePlan{SourceDomain: sourceDomain, TargetDomain: targetDomain}

	source, err := readSiteMetadata(sourceDomain)
	if err != nil {
		plan.Reason = fmt.Sprintf("%s is not a site ServerDeck manages", sourceDomain)
		return plan, nil
	}
	plan.Kind = source.Kind

	if !domainPattern.MatchString(targetDomain) || len(targetDomain) > 253 {
		plan.Reason = "The staging domain is not a valid host name"
		return plan, nil
	}
	if targetDomain == sourceDomain {
		plan.Reason = "The staging domain must differ from the live domain"
		return plan, nil
	}
	if _, err := readSiteMetadata(targetDomain); err == nil {
		plan.Reason = fmt.Sprintf("%s already exists on this server", targetDomain)
		return plan, nil
	}

	plan.FilesBytes = directorySize(filepath.Dir(source.Root))
	plan.IsWordPress = isWordPressApp(sourceDomain)

	if plan.IsWordPress {
		if app, err := readInstalledApp(sourceDomain); err == nil {
			plan.SourceDatabase = app.Database
			plan.DatabaseBytes = databaseSize(app.Database)
		} else {
			plan.Warnings = append(plan.Warnings,
				"This looks like WordPress but ServerDeck has no record of its database, so only files will be copied.")
			plan.IsWordPress = false
		}
	}

	var stat syscall.Statfs_t
	if syscall.Statfs("/var/www", &stat) == nil {
		plan.FreeBytes = int64(stat.Bavail) * int64(stat.Bsize)
	}

	// Copying needs room for the files plus the database dump, with headroom so
	// a clone can never be the thing that fills the disk.
	required := plan.FilesBytes + plan.DatabaseBytes*2
	if plan.FreeBytes > 0 && plan.FreeBytes < required+512*1024*1024 {
		plan.Reason = fmt.Sprintf("Not enough free disk space: this needs about %s and %s is available",
			humanBytes(required), humanBytes(plan.FreeBytes))
		return plan, nil
	}

	if !plan.IsWordPress && plan.Kind == "php" {
		plan.Warnings = append(plan.Warnings,
			"This is a PHP site that is not WordPress. Files are copied as-is; any database connection settings in its code still point at the live database and must be changed by hand.")
	}

	plan.Allowed = true
	return plan, nil
}

// cloneSite performs the clone, reporting progress as it goes.
func cloneSite(sourceDomain, targetDomain string) (cloneResult, error) {
	result := cloneResult{}
	if os.Geteuid() != 0 {
		return result, errors.New("site-clone must run as root")
	}

	plan, err := planClone(sourceDomain, targetDomain)
	if err != nil {
		return result, err
	}
	if !plan.Allowed {
		return result, errors.New(plan.Reason)
	}
	source, err := readSiteMetadata(sourceDomain)
	if err != nil {
		return result, err
	}

	// Anything created below is torn down if a later step fails, so a failed
	// clone never leaves a half-built site serving traffic.
	created := []func(){}
	rollback := func() {
		for index := len(created) - 1; index >= 0; index-- {
			created[index]()
		}
	}

	emitProgress("site", "running", "Creating "+targetDomain)
	kind := source.Kind
	if kind != "php" && kind != "static" {
		kind = "static"
	}
	newSite, err := createSite(targetDomain, kind)
	if err != nil {
		return result, fmt.Errorf("create staging site: %w", err)
	}
	created = append(created, func() { _ = deleteSite(targetDomain, true) })

	emitProgress("files", "running", "Copying website files")
	if err := copyTree(source.Root, newSite.Root); err != nil {
		rollback()
		return result, fmt.Errorf("copy files: %w", err)
	}

	record := stagingRecord{
		Domain:       targetDomain,
		SourceDomain: sourceDomain,
		Kind:         kind,
		IsWordPress:  plan.IsWordPress,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	if plan.IsWordPress {
		emitProgress("database", "running", "Copying the database")
		database, user, password, err := cloneWordPressDatabase(plan.SourceDatabase, targetDomain)
		if err != nil {
			rollback()
			return result, err
		}
		created = append(created, func() { _ = deleteDatabase(database) })
		record.Database, record.DatabaseUser = database, user

		emitProgress("config", "running", "Rewriting wp-config.php")
		if err := rewriteWPConfig(newSite.Root, database, user, password); err != nil {
			rollback()
			return result, fmt.Errorf("update wp-config.php: %w", err)
		}

		emitProgress("urls", "running", "Updating site URLs")
		if err := rewriteWordPressURLs(newSite.Root, sourceDomain, targetDomain); err != nil {
			rollback()
			return result, fmt.Errorf("update site URLs: %w", err)
		}

		emitProgress("safety", "running", "Applying staging safeguards")
		result.Warnings = append(result.Warnings, hardenStagingWordPress(newSite.Root)...)

		// Record the clone as an installed app so the WordPress page manages it
		// like any other site.
		_ = writeInstalledApp(installedApp{
			App:          "wordpress",
			Name:         targetDomain,
			Domain:       targetDomain,
			Database:     database,
			DatabaseUser: user,
			InstalledAt:  record.CreatedAt,
		})
		created = append(created, func() {
			_ = os.Remove(filepath.Join("/var/lib/serverdeck/apps", targetDomain+".json"))
		})
	}

	if err := writeStagingRecord(record); err != nil {
		rollback()
		return result, err
	}

	emitProgress("done", "succeeded", "Staging site ready at "+targetDomain)
	_ = writeAudit("site.cloned", true, sourceDomain+" -> "+targetDomain)

	result.Staging = record
	result.Site = newSite
	result.Warnings = append(result.Warnings,
		"Staging is served over plain HTTP until you issue a certificate for it, and will not resolve until DNS points "+targetDomain+" at this server.")
	return result, nil
}

// refreshStaging re-copies the live site over an existing staging site.
func refreshStaging(stagingDomain string) (cloneResult, error) {
	result := cloneResult{}
	if os.Geteuid() != 0 {
		return result, errors.New("staging-refresh must run as root")
	}
	record, err := readStagingRecord(stagingDomain)
	if err != nil {
		return result, fmt.Errorf("%s is not a staging site ServerDeck created", stagingDomain)
	}

	staging, err := readSiteMetadata(stagingDomain)
	if err != nil {
		return result, err
	}
	source, err := readSiteMetadata(record.SourceDomain)
	if err != nil {
		return result, fmt.Errorf("the live site %s no longer exists", record.SourceDomain)
	}

	// Capture the staging credentials before the copy replaces wp-config.php
	// with the live one. Doing this first also means a failure here aborts before
	// anything has been overwritten.
	password := ""
	if record.IsWordPress && record.Database != "" {
		password, err = readWPConfigPassword(staging.Root)
		if err != nil {
			return result, fmt.Errorf("read the staging database credentials: %w", err)
		}
	}

	emitProgress("files", "running", "Replacing staging files from "+record.SourceDomain)
	if err := copyTree(source.Root, staging.Root); err != nil {
		return result, fmt.Errorf("copy files: %w", err)
	}

	if record.IsWordPress && record.Database != "" {
		app, err := readInstalledApp(record.SourceDomain)
		if err != nil {
			return result, fmt.Errorf("the live site's database is no longer known")
		}
		emitProgress("database", "running", "Replacing the staging database")
		if err := copyDatabaseContents(app.Database, record.Database); err != nil {
			return result, err
		}
		emitProgress("config", "running", "Rewriting wp-config.php")
		if err := rewriteWPConfig(staging.Root, record.Database, record.DatabaseUser, password); err != nil {
			return result, err
		}
		emitProgress("urls", "running", "Updating site URLs")
		if err := rewriteWordPressURLs(staging.Root, record.SourceDomain, stagingDomain); err != nil {
			return result, err
		}
		emitProgress("safety", "running", "Reapplying staging safeguards")
		result.Warnings = append(result.Warnings, hardenStagingWordPress(staging.Root)...)
	}

	record.RefreshedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeStagingRecord(record); err != nil {
		return result, err
	}

	emitProgress("done", "succeeded", "Staging refreshed from "+record.SourceDomain)
	_ = writeAudit("staging.refreshed", true, record.SourceDomain+" -> "+stagingDomain)
	result.Staging = record
	result.Site = staging
	return result, nil
}

func listStaging() ([]stagingRecord, error) {
	records := []stagingRecord{}
	entries, err := os.ReadDir(stagingMetadataDir)
	if err != nil {
		return records, nil
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		record, err := readStagingRecord(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			continue
		}
		// Drop records whose site has been deleted so the list cannot show
		// staging entries that no longer exist.
		if _, err := readSiteMetadata(record.Domain); err != nil {
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

// MARK: - WordPress specifics

// hardenStagingWordPress applies the safeguards that stop a copy of a live site
// behaving like the real one. Failures are reported as warnings rather than
// aborting: an unindexed staging site is far better than no staging site, but
// the user must be told which safeguard did not apply.
func hardenStagingWordPress(root string) []string {
	warnings := []string{}

	// Ask search engines not to index the copy.
	if output, err := runWPCLI(root, "option", "update", "blog_public", "0"); err != nil {
		warnings = append(warnings, "Could not set the search engine visibility flag: "+tail(string(output), 200))
	}
	robots := "User-agent: *\nDisallow: /\n"
	if err := atomicWrite(filepath.Join(root, "robots.txt"), []byte(robots), 0644); err != nil {
		warnings = append(warnings, "Could not write robots.txt to block crawlers.")
	}

	// Stop the clone emailing real customers. A must-use plugin is used because
	// it loads before everything else and cannot be switched off from wp-admin.
	muDir := filepath.Join(root, "wp-content", "mu-plugins")
	if err := os.MkdirAll(muDir, 0755); err != nil {
		warnings = append(warnings, "Could not create the mu-plugins directory, so outgoing email is NOT disabled on staging.")
		return warnings
	}
	plugin := `<?php
/**
 * Plugin Name: ServerDeck Staging Safeguards
 * Description: Disables outgoing email and search engine indexing on a staging copy.
 *
 * Written by ServerDeck when this site was cloned. Deleting this file allows the
 * staging site to send real email.
 */
add_filter( 'pre_wp_mail', function ( $null, $atts ) {
    return true; // Pretend the message was sent, without sending it.
}, 10, 2 );

add_filter( 'pre_option_blog_public', function () {
    return '0';
} );
`
	if err := atomicWrite(filepath.Join(muDir, "serverdeck-staging.php"), []byte(plugin), 0644); err != nil {
		warnings = append(warnings, "Could not install the staging safeguard plugin, so outgoing email is NOT disabled.")
		return warnings
	}
	if credential, err := wwwDataCredential(); err == nil {
		_ = os.Chown(muDir, int(credential.Uid), int(credential.Gid))
		_ = os.Chown(filepath.Join(muDir, "serverdeck-staging.php"), int(credential.Uid), int(credential.Gid))
	}
	return warnings
}

// rewriteWordPressURLs rewrites the live domain to the staging domain across the
// database. This is the step that actually makes a WordPress clone usable:
// WordPress stores absolute URLs, including inside serialised option values, so
// a plain SQL replace would corrupt them. wp search-replace understands the
// serialisation and rewrites lengths correctly.
func rewriteWordPressURLs(root, sourceDomain, targetDomain string) error {
	pairs := [][2]string{
		{"https://" + sourceDomain, "https://" + targetDomain},
		{"http://" + sourceDomain, "http://" + targetDomain},
		{"//" + sourceDomain, "//" + targetDomain},
	}
	for _, pair := range pairs {
		output, err := runWPCLI(root, "search-replace", pair[0], pair[1],
			"--all-tables", "--precise", "--skip-columns=guid", "--report-changed-only")
		if err != nil {
			return fmt.Errorf("%s: %s", pair[0], tail(string(output), 400))
		}
	}
	// siteurl and home are the two options that decide where WordPress thinks it
	// lives; set them explicitly in case the replacements above missed a form.
	for _, option := range []string{"siteurl", "home"} {
		if output, err := runWPCLI(root, "option", "update", option, "http://"+targetDomain); err != nil {
			return fmt.Errorf("set %s: %s", option, tail(string(output), 200))
		}
	}
	return nil
}

// Deliberately not anchored to the start of a line: `<?php define('DB_NAME', …)`
// on a single line is valid and appears in real configs, and anchoring would
// abort the clone on those. Every match is replaced rather than just the first,
// so no live credential can survive anywhere in the file. A commented-out define
// keeps its comment marker, because the match begins at `define(`.
// The value is matched with escape awareness, not "everything up to the next
// quote". A password containing a quote is stored escaped, and a naive pattern
// would stop at that escaped quote and fail to match the define at all — which
// aborts a refresh on exactly the sites whose password happens to contain one.
func definePattern(constant string) *regexp.Regexp {
	return regexp.MustCompile(
		`define\(\s*['"]` + constant + `['"]\s*,\s*(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")\s*\)\s*;`)
}

var (
	dbNameDefine     = definePattern("DB_NAME")
	dbUserDefine     = definePattern("DB_USER")
	dbPasswordDefine = definePattern("DB_PASSWORD")
)

// rewriteWPConfig points the cloned wp-config.php at the cloned database.
//
// Getting this wrong is the one failure that would let staging write to the live
// database, so it verifies every constant was actually replaced.
func rewriteWPConfig(root, database, user, password string) error {
	path := filepath.Join(root, "wp-config.php")
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	replacements := []struct {
		pattern *regexp.Regexp
		value   string
		name    string
	}{
		{dbNameDefine, fmt.Sprintf("define( 'DB_NAME', '%s' );", database), "DB_NAME"},
		{dbUserDefine, fmt.Sprintf("define( 'DB_USER', '%s' );", user), "DB_USER"},
		{dbPasswordDefine, fmt.Sprintf("define( 'DB_PASSWORD', '%s' );", escapePHPSingleQuoted(password)), "DB_PASSWORD"},
	}
	updated := string(contents)
	for _, replacement := range replacements {
		if !replacement.pattern.MatchString(updated) {
			return fmt.Errorf("could not find the %s setting in wp-config.php; the staging site was not connected to its own database", replacement.name)
		}
		updated = replacement.pattern.ReplaceAllLiteralString(updated, replacement.value)
	}

	if err := atomicWrite(path, []byte(updated), 0640); err != nil {
		return err
	}
	if credential, err := wwwDataCredential(); err == nil {
		_ = os.Chown(path, int(credential.Uid), int(credential.Gid))
	}
	return nil
}

func escapePHPSingleQuoted(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `'`, `\'`)
}

// MARK: - Database helpers

// cloneWordPressDatabase creates a database for the staging site and copies the
// live contents into it.
//
// The password is carried out of here rather than read back later: createDatabase
// intentionally strips it before writing the metadata file, so it exists only in
// the value it returns.
func cloneWordPressDatabase(sourceDatabase, targetDomain string) (name, user, password string, err error) {
	name = databaseNameForDomain(targetDomain)
	user = name
	if len(user) > 32 {
		user = user[:32] // MySQL user names are limited to 32 characters.
	}

	created, err := createDatabase(name, user)
	if err != nil {
		return "", "", "", fmt.Errorf("create staging database: %w", err)
	}
	if created.Password == "" {
		_ = deleteDatabase(name)
		return "", "", "", errors.New("the staging database was created without a password")
	}
	if err := copyDatabaseContents(sourceDatabase, name); err != nil {
		_ = deleteDatabase(name)
		return "", "", "", err
	}
	return name, user, created.Password, nil
}

// copyDatabaseContents dumps one database straight into another.
//
// The dump is streamed through a pipe rather than staged on disk: these run on
// servers chosen for being small, and a temporary file would double the space a
// clone needs at its peak.
func copyDatabaseContents(sourceDatabase, targetDatabase string) error {
	client := "mariadb"
	dumper := "mariadb-dump"
	if _, err := runQuick("sh", "-c", "command -v mariadb-dump"); err != nil {
		client, dumper = "mysql", "mysqldump"
	}

	// Recreate the target schema first. A dump only drops the tables it contains,
	// so refreshing staging would otherwise leave behind tables belonging to
	// plugins that have since been removed from the live site. Privileges are
	// stored separately from the schema, so the staging user keeps its access.
	reset := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`; CREATE DATABASE `%s`;",
		escapeBacktickIdentifier(targetDatabase), escapeBacktickIdentifier(targetDatabase))
	if output, err := runWithTimeout(longTimeout, client, "-e", reset); err != nil {
		return fmt.Errorf("prepare the staging database: %s", tail(string(output), 400))
	}

	// Streamed through a pipe rather than staged on disk: these run on servers
	// chosen for being small, and a temporary file would double the peak space.
	// pipefail matters here — without it the exit status would be the importer's,
	// hiding a dump that failed halfway and silently producing a partial copy.
	script := fmt.Sprintf("set -o pipefail; %s --single-transaction --routines --triggers %s | %s %s",
		dumper, shellQuote(sourceDatabase), client, shellQuote(targetDatabase))
	if output, err := runWithTimeout(longTimeout, "bash", "-c", script); err != nil {
		return fmt.Errorf("copy database: %s", tail(string(output), 600))
	}
	return nil
}

func databaseNameForDomain(domain string) string {
	sanitised := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(domain), "_")
	name := "wordpress_" + strings.Trim(sanitised, "_")
	if len(name) > 60 {
		name = name[:60]
	}
	return name
}

// readWPConfigPassword recovers the staging database password from the staging
// site's own wp-config.php.
//
// It cannot be read back from the database metadata, which never stores it. This
// matters on refresh: copying the live tree over staging replaces wp-config.php
// with the live one, so the staging credentials have to be captured beforehand
// and written back afterwards. Without this, a refreshed staging site would
// point straight at the live database.
func readWPConfigPassword(root string) (string, error) {
	contents, err := os.ReadFile(filepath.Join(root, "wp-config.php"))
	if err != nil {
		return "", err
	}
	match := dbPasswordValue.FindSubmatch(contents)
	if len(match) != 3 {
		return "", errors.New("could not read the staging database password from wp-config.php")
	}
	// Exactly one of the two alternatives matches, depending on the quote style.
	value := match[1]
	if len(value) == 0 {
		value = match[2]
	}
	return unescapePHPSingleQuoted(string(value)), nil
}

// The value is matched with escape awareness rather than "everything up to the
// next quote": a generated password containing a quote is written escaped, and a
// naive pattern would stop early and silently recover the wrong password.
// RE2 has no backreferences, so each quote style needs its own alternative.
var dbPasswordValue = regexp.MustCompile(
	`define\(\s*['"]DB_PASSWORD['"]\s*,\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")\s*\)\s*;`)

func unescapePHPSingleQuoted(value string) string {
	value = strings.ReplaceAll(value, `\'`, `'`)
	return strings.ReplaceAll(value, `\\`, `\`)
}

// MARK: - Filesystem helpers

// copyTree mirrors one directory onto another, preferring rsync when present
// because it is far cheaper on a refresh (only changed files move).
func copyTree(source, target string) error {
	source = strings.TrimSuffix(source, "/") + "/"
	target = strings.TrimSuffix(target, "/") + "/"
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}

	if _, err := runQuick("sh", "-c", "command -v rsync"); err == nil {
		if output, err := runWithTimeout(longTimeout, "rsync", "-a", "--delete", source, target); err != nil {
			return fmt.Errorf("%s", tail(string(output), 600))
		}
	} else {
		// cp cannot mirror deletions, so clear the target first to keep refresh
		// semantics identical whichever tool is available.
		if output, err := runWithTimeout(longTimeout, "sh", "-c",
			fmt.Sprintf("rm -rf %s && mkdir -p %s && cp -a %s. %s",
				shellQuote(target), shellQuote(target), shellQuote(source), shellQuote(target))); err != nil {
			return fmt.Errorf("%s", tail(string(output), 600))
		}
	}

	if credential, err := wwwDataCredential(); err == nil {
		_, _ = runWithTimeout(longTimeout, "chown", "-R",
			strconv.Itoa(int(credential.Uid))+":"+strconv.Itoa(int(credential.Gid)), strings.TrimSuffix(target, "/"))
	}
	return nil
}

func directorySize(path string) int64 {
	var total int64
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

func databaseSize(name string) int64 {
	if name == "" {
		return 0
	}
	client := "mariadb"
	if _, err := runQuick("sh", "-c", "command -v mariadb"); err != nil {
		client = "mysql"
	}
	query := fmt.Sprintf(
		"SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema='%s';",
		strings.ReplaceAll(name, "'", ""))
	output, err := runQuick(client, "-N", "-B", "-e", query)
	if err != nil {
		return 0
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func humanBytes(value int64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exp := int64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(value)/float64(div), "KMGT"[exp])
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// escapeBacktickIdentifier makes a name safe inside `backticks`. Database names
// are already validated on creation, so this is defence in depth rather than the
// only thing standing between a name and the SQL parser.
func escapeBacktickIdentifier(value string) string {
	return strings.ReplaceAll(value, "`", "``")
}

// MARK: - Metadata
//
// Sites, databases, and apps each keep a JSON record under /var/lib/serverdeck.
// These read them back; the write paths already exist next to the code that
// creates each kind of record.

func readSiteMetadata(domain string) (site, error) {
	var value site
	contents, err := os.ReadFile(filepath.Join("/var/lib/serverdeck/sites", domain+".json"))
	if err != nil {
		return value, err
	}
	if err := jsonUnmarshal(contents, &value); err != nil {
		return value, err
	}
	if value.Root == "" {
		// Older records predate the stored root; derive the conventional one.
		value.Root = filepath.Join("/var/www", domain, "public")
	}
	return value, nil
}

func writeInstalledApp(record installedApp) error {
	if err := os.MkdirAll("/var/lib/serverdeck/apps", 0755); err != nil {
		return err
	}
	encoded, err := jsonMarshalIndent(record)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join("/var/lib/serverdeck/apps", record.Domain+".json"), append(encoded, '\n'), 0644)
}

func writeStagingRecord(record stagingRecord) error {
	if err := os.MkdirAll(stagingMetadataDir, 0755); err != nil {
		return err
	}
	encoded, err := jsonMarshalIndent(record)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(stagingMetadataDir, record.Domain+".json"), append(encoded, '\n'), 0644)
}

func readStagingRecord(domain string) (stagingRecord, error) {
	var record stagingRecord
	contents, err := os.ReadFile(filepath.Join(stagingMetadataDir, domain+".json"))
	if err != nil {
		return record, err
	}
	return record, jsonUnmarshal(contents, &record)
}

func removeStagingRecord(domain string) {
	_ = os.Remove(filepath.Join(stagingMetadataDir, domain+".json"))
}

// Thin wrappers so this file does not import encoding/json directly for what is
// a single convention shared with the rest of the agent.
func jsonMarshalIndent(value any) ([]byte, error) { return json.MarshalIndent(value, "", "  ") }
func jsonUnmarshal(data []byte, into any) error   { return json.Unmarshal(data, into) }
