package main

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxAppArchiveEntries = 500_000
	maxAppExpandedBytes  = int64(32 * 1024 * 1024 * 1024)
)

func safeArchiveRelative(name string) (string, error) {
	name = strings.TrimPrefix(name, "./")
	clean := filepath.Clean(name)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return clean, nil
}

func appTarReader(path, format string) (io.ReadCloser, *tar.Reader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	var reader io.Reader = file
	closer := io.ReadCloser(file)
	if format == "tar.gz" {
		gz, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			return nil, nil, err
		}
		reader = gz
		closer = &combinedReadCloser{Reader: gz, close: func() error {
			first := gz.Close()
			second := file.Close()
			if first != nil {
				return first
			}
			return second
		}}
	} else if format == "tar.bz2" {
		reader = bzip2.NewReader(file)
	} else {
		file.Close()
		return nil, nil, errors.New("unsupported tar format")
	}
	return closer, tar.NewReader(reader), nil
}

type combinedReadCloser struct {
	io.Reader
	close func() error
}

func (value *combinedReadCloser) Close() error { return value.close() }

func inspectAppTar(path, format string) (int64, error) {
	closer, reader, err := appTarReader(path, format)
	if err != nil {
		return 0, err
	}
	defer closer.Close()
	var total int64
	entries := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		entries++
		if entries > maxAppArchiveEntries {
			return 0, errors.New("application archive contains too many entries")
		}
		if _, err := safeArchiveRelative(header.Name); err != nil {
			return 0, err
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return 0, fmt.Errorf("application archive entry %q is a link or special file", header.Name)
		}
		if header.Size < 0 || header.Size > maxAppExpandedBytes-total {
			return 0, errors.New("application archive expands beyond the 32 GB safety limit")
		}
		total += header.Size
	}
	return total, nil
}

func extractAppTar(path, format, staging string) error {
	closer, reader, err := appTarReader(path, format)
	if err != nil {
		return err
	}
	defer closer.Close()
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name, err := safeArchiveRelative(header.Name)
		if err != nil {
			return err
		}
		target := filepath.Join(staging, name)
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		mode := os.FileMode(header.Mode) & 0777
		mode &^= 06000
		if mode == 0 {
			mode = 0644
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		written, copyErr := io.CopyN(output, reader, header.Size)
		closeErr := output.Close()
		if copyErr != nil || written != header.Size {
			return errors.New("application archive entry is truncated")
		}
		if closeErr != nil {
			return closeErr
		}
	}
}

func inspectAppZip(path string) (int64, error) {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return 0, err
	}
	defer reader.Close()
	if len(reader.File) > maxAppArchiveEntries {
		return 0, errors.New("application archive contains too many entries")
	}
	var total int64
	for _, entry := range reader.File {
		if _, err := safeArchiveRelative(entry.Name); err != nil {
			return 0, err
		}
		if entry.Mode()&os.ModeSymlink != 0 || (!entry.FileInfo().Mode().IsRegular() && !entry.FileInfo().IsDir()) {
			return 0, fmt.Errorf("application archive entry %q is a link or special file", entry.Name)
		}
		size := int64(entry.UncompressedSize64)
		if size < 0 || size > maxAppExpandedBytes-total {
			return 0, errors.New("application archive expands beyond the 32 GB safety limit")
		}
		total += size
	}
	return total, nil
}

func extractAppZip(path, staging string) error {
	reader, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer reader.Close()
	for _, entry := range reader.File {
		name, err := safeArchiveRelative(entry.Name)
		if err != nil {
			return err
		}
		target := filepath.Join(staging, name)
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		input, err := entry.Open()
		if err != nil {
			return err
		}
		mode := entry.Mode().Perm() &^ 06000
		if mode == 0 {
			mode = 0644
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			input.Close()
			return err
		}
		written, copyErr := io.CopyN(output, input, int64(entry.UncompressedSize64))
		input.Close()
		closeErr := output.Close()
		if copyErr != nil || written != int64(entry.UncompressedSize64) {
			return errors.New("application archive entry is truncated")
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func extractAppArchive(archivePath, format, staging string) error {
	var expanded int64
	var err error
	switch format {
	case "tar.gz", "tar.bz2":
		expanded, err = inspectAppTar(archivePath, format)
	case "zip":
		expanded, err = inspectAppZip(archivePath)
	default:
		return errors.New("unsupported archive format")
	}
	if err != nil {
		return fmt.Errorf("validate application archive: %w", err)
	}
	if err := ensureRoomFor(staging, expanded); err != nil {
		return err
	}
	switch format {
	case "tar.gz", "tar.bz2":
		err = extractAppTar(archivePath, format, staging)
	case "zip":
		err = extractAppZip(archivePath, staging)
	}
	if err != nil {
		return fmt.Errorf("extract application: %w", err)
	}
	return nil
}
