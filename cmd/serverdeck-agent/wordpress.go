package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// WordPress manager: lists one-click WordPress sites and manages basic settings
// through WP-CLI (run as www-data in the site docroot). WP-CLI is installed on
// demand from a pinned, checksum-verified release.

const (
	wpCLIVersion = "2.12.0"
	wpCLISHA256  = "ce34ddd838f7351d6759068d09793f26755463b4a4610a5a5c0a97b68220d85c"
	wpCLIPath    = "/usr/local/bin/wp"
)

var wpUserLoginPattern = regexp.MustCompile(`^[A-Za-z0-9 _.@-]{1,60}$`)

type wpUser struct {
	Login string `json:"login"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type wpSite struct {
	Domain          string   `json:"domain"`
	Root            string   `json:"root"`
	Database        string   `json:"database,omitempty"`
	Installed       bool     `json:"installed"`
	Version         string   `json:"version,omitempty"`
	UpdateAvailable bool     `json:"updateAvailable"`
	Title           string   `json:"title,omitempty"`
	Tagline         string   `json:"tagline,omitempty"`
	URL             string   `json:"url,omitempty"`
	AdminEmail      string   `json:"adminEmail,omitempty"`
	Permalink       string   `json:"permalink,omitempty"`
	SearchVisible   bool     `json:"searchVisible"`
	Users           []wpUser `json:"users"`
	Warning         string   `json:"warning,omitempty"`
}

func wpDownloadFile(url, dest string) error {
	client := &http.Client{Timeout: 180 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, response.StatusCode)
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, response.Body)
	return err
}

// ensureWPCLI installs the pinned WP-CLI phar if it isn't already present and
// verified, and returns its path.
func ensureWPCLI() (string, error) {
	if hash, err := fileSHA256(wpCLIPath); err == nil && hash == wpCLISHA256 {
		return wpCLIPath, nil
	}
	if os.Geteuid() != 0 {
		return "", errors.New("installing WP-CLI requires root")
	}
	url := fmt.Sprintf("https://github.com/wp-cli/wp-cli/releases/download/v%s/wp-cli-%s.phar", wpCLIVersion, wpCLIVersion)
	tmp := wpCLIPath + ".download"
	if err := wpDownloadFile(url, tmp); err != nil {
		return "", fmt.Errorf("download WP-CLI: %w", err)
	}
	hash, err := fileSHA256(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if hash != wpCLISHA256 {
		_ = os.Remove(tmp)
		return "", errors.New("WP-CLI checksum verification failed")
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, wpCLIPath); err != nil {
		return "", err
	}
	_ = writeAudit("wpcli.installed", true, wpCLIVersion)
	return wpCLIPath, nil
}

func wwwDataCredential() (*syscall.Credential, error) {
	account, err := user.Lookup("www-data")
	if err != nil {
		return nil, errors.New("the www-data user was not found")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return nil, err
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, nil
}

// runWPCLI executes a WP-CLI command as www-data against a site's docroot.
func runWPCLI(root string, args ...string) ([]byte, error) {
	wp, err := ensureWPCLI()
	if err != nil {
		return nil, err
	}
	credential, err := wwwDataCredential()
	if err != nil {
		return nil, err
	}
	arguments := append([]string{"--path=" + root, "--no-color"}, args...)
	command := exec.Command(wp, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
	command.Env = append(os.Environ(), "HOME=/tmp", "WP_CLI_CACHE_DIR=/tmp/.wp-cli-cache")
	return command.CombinedOutput()
}

func readInstalledApp(domain string) (installedApp, error) {
	var record installedApp
	data, err := os.ReadFile(filepath.Join("/var/lib/serverdeck/apps", domain+".json"))
	if err != nil {
		return record, err
	}
	err = json.Unmarshal(data, &record)
	return record, err
}

func isWordPressApp(domain string) bool {
	record, err := readInstalledApp(domain)
	return err == nil && record.App == "wordpress"
}

func wordpressSiteRoot(domain string) (string, error) {
	data, err := os.ReadFile(filepath.Join("/var/lib/serverdeck/sites", domain+".json"))
	if err != nil {
		return "", errors.New("managed site metadata was not found")
	}
	var value site
	if err := json.Unmarshal(data, &value); err != nil {
		return "", err
	}
	if value.Root == "" {
		return "", errors.New("site has no document root")
	}
	return value.Root, nil
}

func wpOption(root, name string) string {
	out, err := runWPCLI(root, "option", "get", name, "--skip-plugins", "--skip-themes")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// listWordPressSites returns a lightweight summary of every managed WordPress
// site (heavier per-site details come from getWordPressSite).
func listWordPressSites() ([]wpSite, error) {
	paths, _ := filepath.Glob("/var/lib/serverdeck/apps/*.json")
	sites := make([]wpSite, 0, len(paths))
	for _, path := range paths {
		domain := strings.TrimSuffix(filepath.Base(path), ".json")
		record, err := readInstalledApp(domain)
		if err != nil || record.App != "wordpress" {
			continue
		}
		root, err := wordpressSiteRoot(domain)
		if err != nil {
			continue
		}
		item := wpSite{Domain: domain, Root: root, Database: record.Database, Users: []wpUser{}}
		if _, err := runWPCLI(root, "core", "is-installed", "--skip-plugins", "--skip-themes"); err == nil {
			item.Installed = true
			if v, err := runWPCLI(root, "core", "version", "--skip-plugins", "--skip-themes"); err == nil {
				item.Version = strings.TrimSpace(string(v))
			}
			item.Title = wpOption(root, "blogname")
			item.URL = wpOption(root, "siteurl")
			if cu, err := runWPCLI(root, "core", "check-update", "--format=json", "--skip-plugins", "--skip-themes"); err == nil {
				var updates []map[string]any
				if json.Unmarshal(cu, &updates) == nil && len(updates) > 0 {
					item.UpdateAvailable = true
				}
			}
		}
		sites = append(sites, item)
	}
	return sites, nil
}

func getWordPressSite(domain string) (wpSite, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) {
		return wpSite{}, errors.New("invalid domain")
	}
	if !isWordPressApp(domain) {
		return wpSite{}, errors.New("not a managed WordPress site")
	}
	root, err := wordpressSiteRoot(domain)
	if err != nil {
		return wpSite{}, err
	}
	item := wpSite{Domain: domain, Root: root, Users: []wpUser{}}
	if record, err := readInstalledApp(domain); err == nil {
		item.Database = record.Database
	}
	if _, err := runWPCLI(root, "core", "is-installed", "--skip-plugins", "--skip-themes"); err != nil {
		// Files are present but the famous 5-minute setup hasn't run yet.
		return item, nil
	}
	item.Installed = true
	if v, err := runWPCLI(root, "core", "version", "--skip-plugins", "--skip-themes"); err == nil {
		item.Version = strings.TrimSpace(string(v))
	}
	item.Title = wpOption(root, "blogname")
	item.Tagline = wpOption(root, "blogdescription")
	item.URL = wpOption(root, "siteurl")
	item.AdminEmail = wpOption(root, "admin_email")
	item.Permalink = wpOption(root, "permalink_structure")
	item.SearchVisible = wpOption(root, "blog_public") != "0"
	if cu, err := runWPCLI(root, "core", "check-update", "--format=json", "--skip-plugins", "--skip-themes"); err == nil {
		var updates []map[string]any
		if json.Unmarshal(cu, &updates) == nil && len(updates) > 0 {
			item.UpdateAvailable = true
		}
	}
	if uOut, err := runWPCLI(root, "user", "list", "--fields=user_login,user_email,roles", "--format=json", "--skip-plugins", "--skip-themes"); err == nil {
		var users []struct {
			UserLogin string `json:"user_login"`
			UserEmail string `json:"user_email"`
			Roles     string `json:"roles"`
		}
		if json.Unmarshal(uOut, &users) == nil {
			for _, u := range users {
				item.Users = append(item.Users, wpUser{Login: u.UserLogin, Email: u.UserEmail, Role: u.Roles})
			}
		}
	}
	return item, nil
}

type wpSettingsUpdate struct {
	Title         *string `json:"title"`
	Tagline       *string `json:"tagline"`
	AdminEmail    *string `json:"adminEmail"`
	Permalink     *string `json:"permalink"`
	SearchVisible *bool   `json:"searchVisible"`
}

func updateWordPressSettings(domain, settingsJSON string) (wpSite, error) {
	if os.Geteuid() != 0 {
		return wpSite{}, errors.New("wp-settings-set must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) || !isWordPressApp(domain) {
		return wpSite{}, errors.New("not a managed WordPress site")
	}
	root, err := wordpressSiteRoot(domain)
	if err != nil {
		return wpSite{}, err
	}
	if _, err := runWPCLI(root, "core", "is-installed", "--skip-plugins", "--skip-themes"); err != nil {
		return wpSite{}, errors.New("WordPress is not set up yet; finish the browser install first")
	}
	var update wpSettingsUpdate
	if err := json.Unmarshal([]byte(settingsJSON), &update); err != nil {
		return wpSite{}, err
	}
	set := func(option, value string) error {
		out, err := runWPCLI(root, "option", "update", option, value, "--skip-plugins", "--skip-themes")
		if err != nil {
			return fmt.Errorf("update %s: %s", option, tail(string(out), 400))
		}
		return nil
	}
	if update.Title != nil {
		if err := set("blogname", *update.Title); err != nil {
			return wpSite{}, err
		}
	}
	if update.Tagline != nil {
		if err := set("blogdescription", *update.Tagline); err != nil {
			return wpSite{}, err
		}
	}
	if update.AdminEmail != nil {
		email := strings.TrimSpace(*update.AdminEmail)
		if !regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`).MatchString(email) {
			return wpSite{}, errors.New("invalid admin email address")
		}
		if err := set("admin_email", email); err != nil {
			return wpSite{}, err
		}
	}
	if update.SearchVisible != nil {
		value := "0"
		if *update.SearchVisible {
			value = "1"
		}
		if err := set("blog_public", value); err != nil {
			return wpSite{}, err
		}
	}
	if update.Permalink != nil {
		if err := set("permalink_structure", *update.Permalink); err != nil {
			return wpSite{}, err
		}
		// Rewrite rules must be regenerated for the new structure to take effect.
		_, _ = runWPCLI(root, "rewrite", "flush", "--hard", "--skip-plugins", "--skip-themes")
	}
	_ = writeAudit("wp.settings.updated", true, domain)
	return getWordPressSite(domain)
}

func resetWordPressPassword(domain, login, password string) error {
	if os.Geteuid() != 0 {
		return errors.New("wp-user-password must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) || !isWordPressApp(domain) {
		return errors.New("not a managed WordPress site")
	}
	if !wpUserLoginPattern.MatchString(login) {
		return errors.New("invalid WordPress user login")
	}
	if len(password) < 6 || len(password) > 200 || strings.ContainsAny(password, "\n\r") {
		return errors.New("password must be 6-200 characters")
	}
	root, err := wordpressSiteRoot(domain)
	if err != nil {
		return err
	}
	// Confirm the user exists before changing anything.
	if _, err := runWPCLI(root, "user", "get", login, "--field=ID", "--skip-plugins", "--skip-themes"); err != nil {
		return errors.New("that user does not exist on this site")
	}
	out, err := runWPCLI(root, "user", "update", login, "--user_pass="+password, "--skip-plugins", "--skip-themes")
	if err != nil {
		return fmt.Errorf("reset password: %s", tail(string(out), 400))
	}
	// Never log the password itself.
	_ = writeAudit("wp.password.reset", true, domain+" user "+login)
	return nil
}

func updateWordPressCore(domain string) (wpSite, error) {
	if os.Geteuid() != 0 {
		return wpSite{}, errors.New("wp-core-update must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) || !isWordPressApp(domain) {
		return wpSite{}, errors.New("not a managed WordPress site")
	}
	root, err := wordpressSiteRoot(domain)
	if err != nil {
		return wpSite{}, err
	}
	emitProgress("wp", "running", "Updating WordPress core for "+domain)
	if out, err := runWPCLI(root, "core", "update", "--skip-plugins", "--skip-themes"); err != nil {
		return wpSite{}, fmt.Errorf("core update: %s", tail(string(out), 600))
	}
	_, _ = runWPCLI(root, "core", "update-db", "--skip-plugins", "--skip-themes")
	emitProgress("wp", "completed", "WordPress core updated")
	_ = writeAudit("wp.core.updated", true, domain)
	return getWordPressSite(domain)
}
