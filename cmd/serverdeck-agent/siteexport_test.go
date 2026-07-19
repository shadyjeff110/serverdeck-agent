package main

import "testing"

func TestImportWarningsKeepRuntimeCredentialsNotice(t *testing.T) {
	merged := mergeImportWarnings([]string{"plan warning"}, []string{"save credentials"})
	if len(merged) != 2 || merged[0] != "plan warning" || merged[1] != "save credentials" {
		t.Fatalf("warnings = %#v", merged)
	}
}

func TestOnlyWordPressImportCreatesWordPressRecord(t *testing.T) {
	if _, ok := importedApplicationRecord(siteExportManifest{IsWordPress: false}, "drupal.example.com", "drupal_db", "drupal_user"); ok {
		t.Fatal("non-WordPress import was registered as WordPress")
	}
	record, ok := importedApplicationRecord(siteExportManifest{IsWordPress: true}, "blog.example.com", "wp_db", "wp_user")
	if !ok || record.App != "wordpress" || record.Database != "wp_db" || record.DatabaseUser != "wp_user" {
		t.Fatalf("record = %+v, %v", record, ok)
	}
}
