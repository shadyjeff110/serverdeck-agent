package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func writeTestAppTar(t *testing.T, entries []archiveTestEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "app.tar.gz")
	file, _ := os.Create(path)
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{Name: entry.name, Typeflag: kind, Linkname: entry.link, Mode: 0755, Size: int64(len(entry.body))}
		if kind == tar.TypeSymlink {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(entry.body) > 0 {
			_, _ = tw.Write(entry.body)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	_ = file.Close()
	return path
}

func TestApplicationArchiveExtractsRegularFiles(t *testing.T) {
	path := writeTestAppTar(t, []archiveTestEntry{{name: "wordpress/index.php", body: []byte("<?php")}})
	destination := t.TempDir()
	if err := extractAppArchive(path, "tar.gz", destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "wordpress", "index.php")); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationArchiveRejectsLinksAndTraversal(t *testing.T) {
	for name, entry := range map[string]archiveTestEntry{
		"link":      {name: "app/config", kind: tar.TypeSymlink, link: "/etc/passwd"},
		"traversal": {name: "../../etc/passwd", body: []byte("bad")},
	} {
		t.Run(name, func(t *testing.T) {
			path := writeTestAppTar(t, []archiveTestEntry{entry})
			if err := extractAppArchive(path, "tar.gz", t.TempDir()); err == nil {
				t.Fatal("malicious archive was accepted")
			}
		})
	}
}
