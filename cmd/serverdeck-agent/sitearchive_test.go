package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type archiveTestEntry struct {
	name string
	kind byte
	body []byte
	link string
}

func writeTestSiteArchive(t *testing.T, entries []archiveTestEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.sdsite")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{Name: entry.name, Typeflag: kind, Mode: 0644, Size: int64(len(entry.body)), Linkname: entry.link}
		if kind == tar.TypeSymlink {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(entry.body) > 0 {
			if _, err := tw.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func validArchiveEntries(t *testing.T) []archiveTestEntry {
	manifest, _ := json.Marshal(siteExportManifest{Format: 1, SourceDomain: "example.com", Kind: "static", FilesBytes: 5})
	return []archiveTestEntry{{name: "./files/index.html", body: []byte("hello")}, {name: "./manifest.json", body: manifest}}
}

func TestSiteArchiveInspectionAndExtraction(t *testing.T) {
	path := writeTestSiteArchive(t, validArchiveEntries(t))
	stats, err := inspectSiteArchive(path)
	if err != nil {
		t.Fatal(err)
	}
	if stats.FilesSize != 5 || stats.Manifest.SourceDomain != "example.com" {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	destination := t.TempDir()
	if _, err := extractValidatedSiteArchive(path, destination); err != nil {
		t.Fatal(err)
	}
	contents, _ := os.ReadFile(filepath.Join(destination, "files", "index.html"))
	if string(contents) != "hello" {
		t.Fatalf("contents = %q", contents)
	}
}

func TestSiteArchiveRejectsTraversalAndLinks(t *testing.T) {
	manifest, _ := json.Marshal(siteExportManifest{Format: 1, SourceDomain: "example.com", Kind: "static"})
	for name, malicious := range map[string]archiveTestEntry{
		"traversal":  {name: "../etc/passwd", body: []byte("x")},
		"symlink":    {name: "files/config", kind: tar.TypeSymlink, link: "/etc/passwd"},
		"unexpected": {name: "root-owned", body: []byte("x")},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeTestSiteArchive(t, []archiveTestEntry{malicious, {name: "manifest.json", body: manifest}})
			if _, err := inspectSiteArchive(path); err == nil {
				t.Fatal("malicious archive was accepted")
			}
		})
	}
}

func TestSiteArchiveRejectsManifestSizeLie(t *testing.T) {
	manifest, _ := json.Marshal(siteExportManifest{Format: 1, SourceDomain: "example.com", Kind: "static", FilesBytes: 1})
	large := make([]byte, 17*1024*1024)
	path := writeTestSiteArchive(t, []archiveTestEntry{{name: "files/large.bin", body: large}, {name: "manifest.json", body: manifest}})
	if _, err := inspectSiteArchive(path); err == nil {
		t.Fatal("archive exceeding its manifest was accepted")
	}
}
