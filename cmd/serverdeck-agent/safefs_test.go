package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedRestoreTargetRejectsTraversal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "example.com", "public")
	for _, candidate := range []string{"../outside", "../../etc/passwd", "/etc/passwd", "."} {
		if _, err := managedRestoreTarget(root, candidate); err == nil {
			t.Errorf("managedRestoreTarget accepted %q", candidate)
		}
	}
	if target, err := managedRestoreTarget(root, "assets/app.css"); err != nil || target != filepath.Join(root, "assets/app.css") {
		t.Fatalf("safe restore target = %q, %v", target, err)
	}
}

func TestTrashNameMustBeOpaqueBasename(t *testing.T) {
	for _, candidate := range []string{"", "../item", "a/b", `a\\b`, "item..backup"} {
		if validTrashName(candidate) {
			t.Errorf("validTrashName accepted %q", candidate)
		}
	}
	if !validTrashName("index.php_1720123456789") {
		t.Fatal("valid trash name was rejected")
	}
}

func TestReplaceManagedFilePreservesPermissions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "wp-config.php")
	if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := replaceManagedFile(root, path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("permissions = %04o", info.Mode().Perm())
	}
	contents, _ := os.ReadFile(path)
	if string(contents) != "new" {
		t.Fatalf("contents = %q", contents)
	}
}

func TestManagedMutationRejectsFinalSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := replaceManagedFile(root, link, []byte("changed")); err == nil {
		t.Fatal("replacement followed a final symlink")
	}
	if err := chmodManagedTarget(root, link, 0644); err == nil {
		t.Fatal("chmod followed a final symlink")
	}
}
