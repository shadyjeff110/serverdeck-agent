package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rewriteWPConfig is the single most dangerous step in a clone: if it silently
// fails to repoint a constant, the staging site writes to the live database.
func TestRewriteWPConfigRepointsEveryCredential(t *testing.T) {
	root := t.TempDir()
	original := `<?php
define( 'DB_NAME', 'wordpress_live' );
define( 'DB_USER', 'live_user' );
define( 'DB_PASSWORD', 'live-password' );
define( 'DB_HOST', 'localhost' );
$table_prefix = 'wp_';
`
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(original), 0640); err != nil {
		t.Fatal(err)
	}

	if err := rewriteWPConfig(root, "wordpress_staging", "staging_user", "new-password"); err != nil {
		t.Fatalf("rewrite failed: %v", err)
	}

	contents, err := os.ReadFile(filepath.Join(root, "wp-config.php"))
	if err != nil {
		t.Fatal(err)
	}
	updated := string(contents)

	for _, leaked := range []string{"wordpress_live", "live_user", "live-password"} {
		if strings.Contains(updated, leaked) {
			t.Errorf("live credential %q survived the rewrite; staging would write to the live database", leaked)
		}
	}
	for _, expected := range []string{"wordpress_staging", "staging_user", "new-password"} {
		if !strings.Contains(updated, expected) {
			t.Errorf("expected %q in the rewritten config", expected)
		}
	}
	if !strings.Contains(updated, "DB_HOST") {
		t.Error("unrelated settings should be preserved")
	}
}

// A config that does not match the expected shape must fail loudly rather than
// leaving the clone pointed at the live database.
func TestRewriteWPConfigFailsWhenAConstantIsMissing(t *testing.T) {
	root := t.TempDir()
	// DB_PASSWORD deliberately absent.
	partial := `<?php
define( 'DB_NAME', 'wordpress_live' );
define( 'DB_USER', 'live_user' );
`
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(partial), 0640); err != nil {
		t.Fatal(err)
	}

	err := rewriteWPConfig(root, "staging", "staging_user", "pw")
	if err == nil {
		t.Fatal("expected an error when a credential could not be repointed")
	}
	if !strings.Contains(err.Error(), "DB_PASSWORD") {
		t.Errorf("the error should name the missing constant, got: %v", err)
	}
}

func TestRewriteWPConfigHandlesQuotingVariants(t *testing.T) {
	cases := map[string]string{
		"double quotes":   `<?php define( "DB_NAME", "live" ); define( "DB_USER", "u" ); define( "DB_PASSWORD", "p" );`,
		"no inner spaces": `<?php define('DB_NAME','live'); define('DB_USER','u'); define('DB_PASSWORD','p');`,
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(config), 0640); err != nil {
				t.Fatal(err)
			}
			if err := rewriteWPConfig(root, "staging_db", "staging_user", "pw"); err != nil {
				t.Fatalf("should handle %s: %v", name, err)
			}
			contents, _ := os.ReadFile(filepath.Join(root, "wp-config.php"))
			if strings.Contains(string(contents), "'live'") || strings.Contains(string(contents), `"live"`) {
				t.Error("live database name survived the rewrite")
			}
		})
	}
}

// A password containing a quote must not break out of the PHP string literal.
func TestPasswordEscapingCannotBreakOutOfPHPString(t *testing.T) {
	root := t.TempDir()
	config := `<?php
define( 'DB_NAME', 'live' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
`
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(config), 0640); err != nil {
		t.Fatal(err)
	}
	if err := rewriteWPConfig(root, "db", "user", `a'b\c`); err != nil {
		t.Fatal(err)
	}
	contents, _ := os.ReadFile(filepath.Join(root, "wp-config.php"))
	if !strings.Contains(string(contents), `'a\'b\\c'`) {
		t.Errorf("password was not escaped for a single-quoted PHP string: %s", contents)
	}
}

func TestDatabaseNameForDomain(t *testing.T) {
	cases := map[string]string{
		"staging.example.com":     "wordpress_staging_example_com",
		"UPPER.Example.COM":       "wordpress_upper_example_com",
		"with--dashes.example.co": "wordpress_with_dashes_example_co",
	}
	for domain, expected := range cases {
		if actual := databaseNameForDomain(domain); actual != expected {
			t.Errorf("%s: expected %q, got %q", domain, expected, actual)
		}
	}

	long := databaseNameForDomain(strings.Repeat("a", 100) + ".com")
	if len(long) > 60 {
		t.Errorf("name must stay within MySQL's limit, got %d chars", len(long))
	}
}

func TestShellQuoteNeutralisesQuotes(t *testing.T) {
	if quoted := shellQuote(`a'b`); quoted != `'a'\''b'` {
		t.Errorf("unexpected quoting: %s", quoted)
	}
}

func TestEscapeBacktickIdentifier(t *testing.T) {
	if escaped := escapeBacktickIdentifier("a`b"); escaped != "a``b" {
		t.Errorf("unexpected escaping: %s", escaped)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		512:                    "512 B",
		1024:                   "1.0 KB",
		5 * 1024 * 1024:        "5.0 MB",
		3 * 1024 * 1024 * 1024: "3.0 GB",
	}
	for value, expected := range cases {
		if actual := humanBytes(value); actual != expected {
			t.Errorf("%d: expected %q, got %q", value, expected, actual)
		}
	}
}

// A refresh copies the live tree over staging, which replaces wp-config.php.
// The staging password must survive that round trip, or the refreshed staging
// site would point at the live database.
func TestStagingPasswordSurvivesAConfigRoundTrip(t *testing.T) {
	root := t.TempDir()
	config := `<?php
define( 'DB_NAME', 'live' );
define( 'DB_USER', 'u' );
define( 'DB_PASSWORD', 'p' );
`
	if err := os.WriteFile(filepath.Join(root, "wp-config.php"), []byte(config), 0640); err != nil {
		t.Fatal(err)
	}

	for _, password := range []string{"simple", `has'quote`, `back\slash`, `both'\mixed`} {
		if err := rewriteWPConfig(root, "staging_db", "staging_user", password); err != nil {
			t.Fatalf("write %q: %v", password, err)
		}
		recovered, err := readWPConfigPassword(root)
		if err != nil {
			t.Fatalf("read back %q: %v", password, err)
		}
		if recovered != password {
			t.Errorf("password did not survive the round trip: wrote %q, read %q", password, recovered)
		}
	}
}
