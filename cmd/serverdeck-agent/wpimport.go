package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Import of All-in-One WP Migration ".wpress" archives.
//
// The .wpress format is a flat concatenation of entries, each preceded by a
// 4377-byte header: 255-byte name, 14-byte ASCII size, 12-byte ASCII mtime, and
// a 4096-byte path prefix. An all-zero header marks the end. AI1WM archives only
// the wp-content tree (stored relative to the archive root) plus database.sql
// and package.json — WordPress core is NOT included. So the import installs a
// fresh WordPress, overlays the archive's wp-content, imports the database, and
// rewrites the old site URL to the new domain.

const (
	wpressHeaderSize = 4377
	wpressNameLen    = 255
	wpressSizeLen    = 14
	wpressMtimeLen   = 12
)

var (
	wpImportSessionPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	wpPrefixPattern        = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)
)

// rewriteSQLPrefix substitutes AI1WM's SERVMASK_PREFIX_ placeholder with the
// destination table prefix. sed streams the file, so this works for large dumps.
func rewriteSQLPrefix(sqlPath, targetPrefix string) error {
	if !wpPrefixPattern.MatchString(targetPrefix) {
		return errors.New("invalid table prefix")
	}
	if output, err := exec.Command("sed", "-i", "s/SERVMASK_PREFIX_/"+targetPrefix+"/g", sqlPath).CombinedOutput(); err != nil {
		return fmt.Errorf("rewrite table prefix: %s", tail(string(output), 300))
	}
	return nil
}

// wpressField reads a fixed-width, null-terminated header field: the value is
// the bytes up to the first null. (Trimming only trailing nulls is wrong — the
// archive writer can leave stray bytes after the terminator.)
func wpressField(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

type wpressPackage struct {
	SiteURL    string   `json:"SiteURL"`
	HomeURL    string   `json:"HomeURL"`
	Template   string   `json:"Template"`
	Stylesheet string   `json:"Stylesheet"`
	Plugins    []string `json:"Plugins"`
	Database   struct {
		Prefix string `json:"Prefix"`
	} `json:"Database"`
	PHP struct {
		Version string `json:"Version"`
	} `json:"PHP"`
}

var (
	wpSlugPattern       = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	wpPluginFilePattern = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,128}$`)
)

// majorVersion returns the leading major component of a version string.
func majorVersion(value string) int {
	parts := strings.SplitN(strings.TrimSpace(value), ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	return major
}

func serverPHPVersion() string {
	output, err := exec.Command("php", "-r", "echo PHP_VERSION;").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// parseWPressPackage reads just the package.json entry to learn the origin URL
// and table prefix without extracting the whole archive.
func parseWPressPackage(archivePath string) (wpressPackage, error) {
	var pkg wpressPackage
	file, err := os.Open(archivePath)
	if err != nil {
		return pkg, err
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, 1<<20)
	header := make([]byte, wpressHeaderSize)
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			return pkg, errors.New("package.json not found in archive")
		}
		if header[0] == 0 {
			return pkg, errors.New("package.json not found in archive")
		}
		name := wpressField(header[0:wpressNameLen])
		size, err := strconv.ParseInt(strings.TrimSpace(wpressField(header[wpressNameLen:wpressNameLen+wpressSizeLen])), 10, 64)
		if err != nil {
			return pkg, fmt.Errorf("invalid archive header size: %w", err)
		}
		if name == "package.json" {
			data := make([]byte, size)
			if _, err := io.ReadFull(reader, data); err != nil {
				return pkg, err
			}
			if err := json.Unmarshal(data, &pkg); err != nil {
				return pkg, fmt.Errorf("parse package.json: %w", err)
			}
			return pkg, nil
		}
		if _, err := io.CopyN(io.Discard, reader, size); err != nil {
			return pkg, err
		}
	}
}

// extractWPress writes the archive's wp-content into docroot/wp-content and the
// bundled database.sql to sqlDest. AI1WM metadata files are skipped.
func extractWPress(archivePath, docroot, sqlDest string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, 1<<20)
	header := make([]byte, wpressHeaderSize)
	contentRoot := filepath.Join(docroot, "wp-content")
	prefixOffset := wpressNameLen + wpressSizeLen + wpressMtimeLen
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return err
		}
		if header[0] == 0 {
			break // end-of-archive marker
		}
		name := wpressField(header[0:wpressNameLen])
		size, err := strconv.ParseInt(strings.TrimSpace(wpressField(header[wpressNameLen:wpressNameLen+wpressSizeLen])), 10, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("invalid archive entry size for %q", name)
		}
		prefix := wpressField(header[prefixOffset : prefixOffset+4096])
		rel := name
		if prefix != "" && prefix != "." {
			rel = prefix + "/" + name
		}
		clean := filepath.Clean(rel)
		if strings.HasPrefix(clean, "..") || strings.HasPrefix(clean, "/") || strings.Contains(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe path in archive: %q", rel)
		}

		var dest string
		skip := false
		switch clean {
		case "database.sql":
			dest = sqlDest
		case "package.json", "multisite.json":
			skip = true
		default:
			dest = filepath.Join(contentRoot, clean)
			// Defense in depth: the resolved path must stay under wp-content.
			if !strings.HasPrefix(dest, contentRoot+string(filepath.Separator)) {
				return fmt.Errorf("path escapes wp-content: %q", rel)
			}
		}
		if skip {
			if _, err := io.CopyN(io.Discard, reader, size); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return err
		}
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		if _, err := io.CopyN(out, reader, size); err != nil {
			out.Close()
			return err
		}
		out.Close()
	}
	return nil
}

func importDatabaseSQL(dbName, engine, sqlPath string) error {
	file, err := os.Open(sqlPath)
	if err != nil {
		return err
	}
	defer file.Close()
	command := exec.Command("mariadb", dbName)
	if engine == "MySQL" {
		command = exec.Command("mysql", dbName)
	}
	command.Stdin = file
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("import database: %s", tail(string(output), 800))
	}
	return nil
}

func databaseEngine(name string) string {
	data, err := os.ReadFile(filepath.Join("/var/lib/serverdeck/databases", name+".json"))
	if err != nil {
		return ""
	}
	var value database
	_ = json.Unmarshal(data, &value)
	return value.Engine
}

func setWPConfigPrefix(docroot, prefix string) error {
	path := filepath.Join(docroot, "wp-config.php")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// ReplaceAllLiteral: the replacement contains "$table_prefix", and the normal
	// Replace expands $-sequences as capture-group references, which would drop
	// the variable name and corrupt wp-config.php.
	replaced := regexp.MustCompile(`\$table_prefix\s*=\s*'[^']*';`).ReplaceAllLiteral(data, []byte("$table_prefix = '"+prefix+"';"))
	return os.WriteFile(path, replaced, 0640)
}

// importWPress runs the full import. The archive must already be uploaded to
// /tmp/serverdeck-import-<session>.wpress.
func importWPress(domain, session string) (wpSite, error) {
	if os.Geteuid() != 0 {
		return wpSite{}, errors.New("wp-import must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if len(domain) > 253 || !domainPattern.MatchString(domain) {
		return wpSite{}, errors.New("invalid domain name")
	}
	if !wpImportSessionPattern.MatchString(session) {
		return wpSite{}, errors.New("invalid import session")
	}
	if _, err := os.Stat(filepath.Join("/var/lib/serverdeck/sites", domain+".json")); err == nil {
		return wpSite{}, errors.New("a managed site with this domain already exists; imports always create a new site")
	}
	archive := filepath.Join("/tmp", "serverdeck-import-"+session+".wpress")
	if _, err := os.Stat(archive); err != nil {
		return wpSite{}, errors.New("the uploaded backup was not found")
	}
	sqlPath := filepath.Join("/tmp", "serverdeck-import-"+session+".sql")
	defer os.Remove(archive)
	defer os.Remove(sqlPath)

	pkg, err := parseWPressPackage(archive)
	if err != nil {
		return wpSite{}, err
	}

	emitProgress("wpimport", "running", "Installing WordPress for "+domain)
	install, err := installApp("wordpress", domain, true)
	if err != nil {
		return wpSite{}, fmt.Errorf("prepare WordPress: %w", err)
	}
	if install.Database == nil {
		return wpSite{}, errors.New("WordPress preparation did not create a database")
	}
	dbName := install.Database.Name

	// From here on, roll the whole thing back on any failure.
	rollback := func() {
		_ = deleteSite(domain, true)
		_ = deleteDatabase(dbName)
		_ = os.Remove(filepath.Join("/var/lib/serverdeck/apps", domain+".json"))
	}

	root, err := wordpressSiteRoot(domain)
	if err != nil {
		rollback()
		return wpSite{}, err
	}

	emitProgress("wpimport", "running", "Extracting backup files")
	if err := extractWPress(archive, root, sqlPath); err != nil {
		rollback()
		return wpSite{}, fmt.Errorf("extract backup: %w", err)
	}

	// AI1WM stores the database with a literal "SERVMASK_PREFIX_" placeholder in
	// place of the real table prefix; substitute the destination prefix and make
	// wp-config agree before importing.
	targetPrefix := "wp_"
	if p := strings.TrimSpace(pkg.Database.Prefix); wpPrefixPattern.MatchString(p) {
		targetPrefix = p
	}
	if err := setWPConfigPrefix(root, targetPrefix); err != nil {
		rollback()
		return wpSite{}, fmt.Errorf("set table prefix: %w", err)
	}
	if err := rewriteSQLPrefix(sqlPath, targetPrefix); err != nil {
		rollback()
		return wpSite{}, err
	}

	emitProgress("wpimport", "running", "Importing database")
	if err := importDatabaseSQL(dbName, databaseEngine(dbName), sqlPath); err != nil {
		rollback()
		return wpSite{}, err
	}

	// Ownership so the web server and WP-CLI can read/write the imported files.
	_ = exec.Command("chown", "-R", "www-data:www-data", filepath.Dir(root)).Run()

	newURL := "https://" + domain
	if old := strings.TrimSpace(pkg.SiteURL); old != "" && old != newURL {
		emitProgress("wpimport", "running", "Rewriting site URL to "+newURL)
		_, _ = runWPCLI(root, "search-replace", old, newURL, "--all-tables", "--skip-columns=guid", "--report-changed-only")
		// Also cover an https origin or bare-scheme references.
		if strings.HasPrefix(old, "http://") {
			_, _ = runWPCLI(root, "search-replace", "https://"+strings.TrimPrefix(old, "http://"), newURL, "--all-tables", "--skip-columns=guid", "--report-changed-only")
		}
	}
	_, _ = runWPCLI(root, "option", "update", "siteurl", newURL)
	_, _ = runWPCLI(root, "option", "update", "home", newURL)

	// AI1WM blanks the theme/plugin options in its dump and carries them in
	// package.json instead; without restoring them WordPress loads no theme at
	// all and renders a blank page.
	emitProgress("wpimport", "running", "Restoring theme and active plugins")
	if wpSlugPattern.MatchString(pkg.Template) {
		_, _ = runWPCLI(root, "option", "update", "template", pkg.Template, "--skip-plugins", "--skip-themes")
	}
	if wpSlugPattern.MatchString(pkg.Stylesheet) {
		_, _ = runWPCLI(root, "option", "update", "stylesheet", pkg.Stylesheet, "--skip-plugins", "--skip-themes")
	}
	plugins := []string{}
	for _, plugin := range pkg.Plugins {
		if wpPluginFilePattern.MatchString(plugin) {
			plugins = append(plugins, plugin)
		}
	}
	if encoded, err := json.Marshal(plugins); err == nil {
		_, _ = runWPCLI(root, "option", "update", "active_plugins", string(encoded), "--format=json", "--skip-plugins", "--skip-themes")
	}

	// Migrate the schema if the imported DB is older than the installed core.
	_, _ = runWPCLI(root, "core", "update-db")
	_, _ = runWPCLI(root, "rewrite", "flush", "--hard")
	_, _ = runWPCLI(root, "cache", "flush")

	emitProgress("wpimport", "completed", "Import complete")
	_ = writeAudit("wp.import.completed", true, domain+" from .wpress")

	imported, err := getWordPressSite(domain)
	if err != nil {
		return imported, err
	}
	// The origin's PHP is recorded in package.json. Running a newer site's
	// themes/plugins on an older PHP typically fails with a blank page, so say
	// so plainly rather than leaving the user to guess.
	serverPHP := serverPHPVersion()
	if originMajor := majorVersion(pkg.PHP.Version); originMajor > 0 {
		if serverMajor := majorVersion(serverPHP); serverMajor > 0 && serverMajor < originMajor {
			imported.Warning = fmt.Sprintf("This backup came from PHP %s, but this server runs PHP %s. Themes or plugins written for PHP %d will fail to parse (usually a blank page). Move this site to a server with PHP %d, or upgrade this server's PHP.", pkg.PHP.Version, serverPHP, originMajor, originMajor)
			emitProgress("wpimport", "warning", imported.Warning)
		}
	}
	return imported, nil
}
