package main

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

func TestManagedServicesAreAllowlisted(t *testing.T) {
	if len(managedServices) == 0 {
		t.Fatal("managed service allowlist is empty")
	}
	if _, ok := managedServices["nginx"]; !ok {
		t.Fatal("nginx must be included")
	}
}

func TestDomainValidation(t *testing.T) {
	valid := []string{"example.com", "app.example.com", "demo.test"}
	invalid := []string{"example", "-bad.example", "bad;touch.example", "../example.com", "UPPER.example"}
	for _, domain := range valid {
		if !domainPattern.MatchString(domain) {
			t.Errorf("expected %q to be valid", domain)
		}
	}
	for _, domain := range invalid {
		if domainPattern.MatchString(domain) {
			t.Errorf("expected %q to be invalid", domain)
		}
	}
}

func TestEncodedDomainUsesShellSafeAlphabet(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte("app.example.com"))
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(encoded) {
		t.Fatalf("unsafe encoded domain: %s", encoded)
	}
}

func TestDatabaseNameValidation(t *testing.T) {
	for _, name := range []string{"app", "app_database", "db123"} {
		if !databaseNamePattern.MatchString(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}
	for _, name := range []string{"1database", "UPPER", "bad-name", "name;drop"} {
		if databaseNamePattern.MatchString(name) {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}

func TestRandomPassword(t *testing.T) {
	password, err := randomPassword(28)
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 28 {
		t.Fatalf("password length = %d", len(password))
	}
}

func TestWebStackPackageListIsFixed(t *testing.T) {
	wanted := map[string]bool{"nginx": true, "mariadb-server": true, "php-fpm": true}
	for _, name := range webStackPackages {
		delete(wanted, name)
	}
	if len(wanted) != 0 {
		t.Fatalf("required packages missing: %v", wanted)
	}
}

func TestTail(t *testing.T) {
	if got := tail("abcdefgh", 4); got != "efgh" {
		t.Fatalf("tail() = %q", got)
	}
}

func TestAppDefinitionsAreReviewed(t *testing.T) {
	seen := map[string]bool{}
	idPattern := regexp.MustCompile(`^[a-z][a-z0-9]*$`)
	for _, definition := range appDefinitions() {
		if !idPattern.MatchString(definition.id) {
			t.Errorf("app ID %q is not a safe identifier", definition.id)
		}
		if seen[definition.id] {
			t.Errorf("duplicate app ID %q", definition.id)
		}
		seen[definition.id] = true
		switch definition.database {
		case "none", "mysql", "any":
		default:
			t.Errorf("app %q has unknown database requirement %q", definition.id, definition.database)
		}
		switch definition.download.format {
		case "tar.gz", "tar.bz2", "zip":
		default:
			t.Errorf("app %q has unsupported archive format %q", definition.id, definition.download.format)
		}
		hasDirect := definition.download.url != ""
		hasGitHub := definition.download.githubRepo != ""
		if hasDirect == hasGitHub {
			t.Errorf("app %q must define exactly one download source", definition.id)
		}
		if hasDirect && !strings.HasPrefix(definition.download.url, "https://") {
			t.Errorf("app %q download must use HTTPS", definition.id)
		}
		if definition.download.checksumURL != "" && !strings.HasPrefix(definition.download.checksumURL, "https://") {
			t.Errorf("app %q checksum must use HTTPS", definition.id)
		}
		if hasGitHub {
			if definition.download.assetPattern == "" {
				t.Errorf("app %q needs an asset pattern", definition.id)
			}
			if _, err := regexp.Compile(definition.download.assetPattern); err != nil {
				t.Errorf("app %q asset pattern does not compile: %v", definition.id, err)
			}
		}
		allowedExtensions := map[string]bool{"curl": true, "mbstring": true, "mysql": true, "xml": true, "zip": true, "opcache": true, "gd": true, "intl": true, "bcmath": true, "soap": true}
		for _, extension := range definition.extensions {
			if !allowedExtensions[extension] {
				t.Errorf("app %q uses extension %q outside the reviewed set", definition.id, extension)
			}
		}
	}
	for _, required := range []string{"wordpress", "nextcloud", "phpmyadmin"} {
		if !seen[required] {
			t.Errorf("catalog is missing %q", required)
		}
	}
}

func TestDatabaseIdentifier(t *testing.T) {
	cases := map[string]string{
		"example.com":  "wordpress_example_com",
		"BLOG.Example": "wordpress_blog_example",
		"a-very-long-domain-name-that-keeps-going.example.com": "wordpress_a_very_long_domain_nam",
	}
	for domain, expected := range cases {
		got := databaseIdentifier("wordpress", domain)
		if got != expected {
			t.Errorf("databaseIdentifier(%q) = %q, expected %q", domain, got, expected)
		}
		if !databaseNamePattern.MatchString(got) {
			t.Errorf("identifier %q is not a valid database name", got)
		}
		if len(got) > 32 {
			t.Errorf("identifier %q exceeds the MySQL user length limit", got)
		}
	}
}

func TestResolveArchiveRootRejectsMissingSubPath(t *testing.T) {
	staging := t.TempDir()
	if _, err := resolveArchiveRoot(staging, "upload"); err == nil {
		t.Fatal("expected an error for a missing archive sub-path")
	}
}
