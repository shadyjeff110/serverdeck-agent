//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const managedTrashRoot = "/var/lib/serverdeck/trash"

// openDirectoryBeneath walks from root one component at a time without ever
// following a symlink. Keeping an open descriptor for every parent closes the
// check/use race that path-based EvalSymlinks checks leave behind.
func openDirectoryBeneath(root, relative string) (int, error) {
	rootFD, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	current := rootFD
	clean := filepath.Clean(relative)
	if clean == "." || clean == "" {
		return current, nil
	}
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		syscall.Close(current)
		return -1, errors.New("path is outside the managed root")
	}
	for _, component := range strings.Split(clean, string(os.PathSeparator)) {
		next, openErr := syscall.Openat(current, component,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(current)
		if openErr != nil {
			return -1, openErr
		}
		current = next
	}
	return current, nil
}

func openManagedTarget(root, target string, flags int) (int, error) {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return -1, errors.New("path is outside the managed root")
	}
	parentFD, err := openDirectoryBeneath(root, filepath.Dir(relative))
	if err != nil {
		return -1, err
	}
	defer syscall.Close(parentFD)
	return syscall.Openat(parentFD, filepath.Base(relative), flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
}

func readManagedFile(root, target string, limit int64) ([]byte, error) {
	fd, err := openManagedTarget(root, target, syscall.O_RDONLY)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(target))
	if file == nil {
		syscall.Close(fd)
		return nil, errors.New("could not open managed file")
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit+1))
}

// replaceManagedFile preserves the existing file's owner and permissions and
// renames within an already-open parent directory. No component can be swapped
// for a symlink between validation and replacement.
func replaceManagedFile(root, target string, data []byte) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("path is outside the managed root")
	}
	parentFD, err := openDirectoryBeneath(root, filepath.Dir(relative))
	if err != nil {
		return err
	}
	defer syscall.Close(parentFD)

	name := filepath.Base(relative)
	existingFD, err := syscall.Openat(parentFD, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(existingFD, &stat); err != nil {
		syscall.Close(existingFD)
		return err
	}
	syscall.Close(existingFD)
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return errors.New("only regular files can be edited")
	}

	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := ".serverdeck-" + hex.EncodeToString(random)
	temporaryFD, err := syscall.Openat(parentFD, temporary,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(stat.Mode&0777))
	if err != nil {
		return err
	}
	cleanup := func() {
		syscall.Close(temporaryFD)
		_ = syscall.Unlinkat(parentFD, temporary)
	}

	file := os.NewFile(uintptr(temporaryFD), temporary)
	if file == nil {
		cleanup()
		return errors.New("could not open the replacement file")
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		_ = syscall.Unlinkat(parentFD, temporary)
		return err
	}
	if err := syscall.Fchmod(temporaryFD, uint32(stat.Mode&0777)); err != nil {
		file.Close()
		_ = syscall.Unlinkat(parentFD, temporary)
		return err
	}
	if err := syscall.Fchown(temporaryFD, int(stat.Uid), int(stat.Gid)); err != nil {
		file.Close()
		_ = syscall.Unlinkat(parentFD, temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = syscall.Unlinkat(parentFD, temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = syscall.Unlinkat(parentFD, temporary)
		return err
	}
	if err := syscall.Renameat(parentFD, temporary, parentFD, name); err != nil {
		_ = syscall.Unlinkat(parentFD, temporary)
		return err
	}
	return nil
}

func chmodManagedTarget(root, target string, mode os.FileMode) error {
	fd, err := openManagedTarget(root, target, syscall.O_RDONLY)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Fchmod(fd, uint32(mode.Perm()))
}

func chownManagedTarget(root, target string, uid, gid int) error {
	fd, err := openManagedTarget(root, target, syscall.O_RDONLY)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Fchown(fd, uid, gid)
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
	if err := os.Chmod(directory, 0700); err != nil {
		return "", err
	}
	return directory, nil
}

func validTrashName(name string) bool {
	return name != "" && name == filepath.Base(name) && !strings.ContainsAny(name, "/\\") && !strings.Contains(name, "..")
}

func managedRestoreTarget(root, relative string) (string, error) {
	clean := filepath.Clean(relative)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("trash entry has an unsafe original path")
	}
	target := filepath.Join(root, clean)
	resolved, err := filepath.Rel(root, target)
	if err != nil || resolved != clean {
		return "", fmt.Errorf("trash entry escapes the website root")
	}
	return target, nil
}
