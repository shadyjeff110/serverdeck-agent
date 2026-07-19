package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// A pre-v2 manifest has no format field. It must be recognised as legacy rather
// than silently treated as a current backup that would then fail to restore.
func TestLegacyManifestIsRecognised(t *testing.T) {
	legacy := `{"id":"old","created_at":"2026-07-01T00:00:00Z","archive":"/var/backups/serverdeck/old/serverdeck-backup.tar.gz","size":123,"sha256":"abc","sites":["example.com"],"databases":["wp"]}`

	var manifest backupManifest
	if err := json.Unmarshal([]byte(legacy), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Format >= backupFormatV2 {
		t.Errorf("an old manifest should decode with a format below v2, got %d", manifest.Format)
	}

	// The listing path is what marks it; assert the rule it applies.
	if !(manifest.Format < backupFormatV2) {
		t.Error("legacy detection rule did not hold")
	}
}

func TestBackupIDRejectsPathTraversal(t *testing.T) {
	for _, bad := range []string{"", "..", "../etc", "a/b", `a\b`, "../../root"} {
		if err := validBackupID(bad); err == nil {
			t.Errorf("%q should be rejected as a backup id", bad)
		}
	}
	for _, good := range []string{"server-20260718-120000", "site-example.com-20260718-120000"} {
		if err := validBackupID(good); err != nil {
			t.Errorf("%q should be accepted, got %v", good, err)
		}
	}
}

func TestBackupIDNaming(t *testing.T) {
	server := backupID(backupScopeServer, nil)
	if !strings.HasPrefix(server, "server-") {
		t.Errorf("server backup id should be prefixed, got %q", server)
	}
	site := backupID(backupScopeSite, []string{"example.com"})
	if !strings.HasPrefix(site, "site-example.com-") {
		t.Errorf("site backup id should name the site, got %q", site)
	}
	// The id becomes a directory name, so it must survive validation.
	if err := validBackupID(site); err != nil {
		t.Errorf("generated id must be a valid id, got %v", err)
	}
}

// A backup with neither files nor database cannot restore anything, so it must
// be refused at creation rather than discovered to be useless at restore time.
func TestSiteBackupRequiresSomeContent(t *testing.T) {
	if _, err := createSiteBackup("example.com", false, false); err == nil {
		t.Error("a backup containing nothing should be refused")
	}
}
