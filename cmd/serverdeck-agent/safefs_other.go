//go:build !linux

package main

// The privileged agent is released only for Linux. These portable equivalents
// keep unit tests runnable on the macOS development host; production uses the
// descriptor-relative implementation in safefs.go.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const managedTrashRoot = "/var/lib/serverdeck/trash"

func ensurePortableManagedPath(root, target string) error {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("path is outside the managed root")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(target))
	if err != nil || (parent != resolvedRoot && !strings.HasPrefix(parent, resolvedRoot+string(os.PathSeparator))) {
		return errors.New("symbolic links outside the website root are not allowed")
	}
	if info, err := os.Lstat(target); err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symbolic links are not managed")
	}
	return nil
}

func replaceManagedFile(root, target string, data []byte) error {
	if err := ensurePortableManagedPath(root, target); err != nil {
		return err
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("only regular files can be edited")
	}
	stat, _ := info.Sys().(*syscall.Stat_t)
	if err := atomicWrite(target, data, info.Mode().Perm()); err != nil {
		return err
	}
	if stat != nil {
		_ = os.Chown(target, int(stat.Uid), int(stat.Gid))
	}
	return nil
}

func readManagedFile(root, target string, limit int64) ([]byte, error) {
	if err := ensurePortableManagedPath(root, target); err != nil {
		return nil, err
	}
	file, err := os.Open(target)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit+1))
}

func chmodManagedTarget(root, target string, mode os.FileMode) error {
	if err := ensurePortableManagedPath(root, target); err != nil {
		return err
	}
	return os.Chmod(target, mode.Perm())
}

func chownManagedTarget(root, target string, uid, gid int) error {
	if err := ensurePortableManagedPath(root, target); err != nil {
		return err
	}
	return os.Chown(target, uid, gid)
}

func managedTrashDirectory(root string) (string, error) {
	domain := filepath.Base(filepath.Dir(root))
	if !domainPattern.MatchString(domain) {
		return "", errors.New("invalid managed website root")
	}
	directory := filepath.Join(managedTrashRoot, domain)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return "", err
	}
	return directory, os.Chmod(directory, 0700)
}

func validTrashName(name string) bool {
	return name != "" && name == filepath.Base(name) && !strings.ContainsAny(name, "/\\") && !strings.Contains(name, "..")
}

func managedRestoreTarget(root, relative string) (string, error) {
	clean := filepath.Clean(relative)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("trash entry has an unsafe original path")
	}
	return filepath.Join(root, clean), nil
}
