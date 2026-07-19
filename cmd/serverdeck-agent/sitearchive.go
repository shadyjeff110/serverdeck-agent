package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxSiteArchiveEntries = 500_000
	maxSiteArchiveBytes   = int64(32 * 1024 * 1024 * 1024)
	maxManifestBytes      = int64(1024 * 1024)
)

type siteArchiveStats struct {
	Manifest     siteExportManifest
	ExpandedSize int64
	Entries      int
	FilesSize    int64
	DatabaseSize int64
}

func cleanSiteArchiveName(name string) (string, error) {
	name = strings.TrimPrefix(name, "./")
	clean := filepath.Clean(name)
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("archive contains an unsafe path")
	}
	if clean == "manifest.json" || clean == "database.sql" || clean == "vhost.conf" || clean == "files" || strings.HasPrefix(clean, "files"+string(os.PathSeparator)) {
		return clean, nil
	}
	return "", fmt.Errorf("archive contains unexpected entry %q", name)
}

func inspectSiteArchive(path string) (siteArchiveStats, error) {
	stats := siteArchiveStats{}
	file, err := os.Open(path)
	if err != nil {
		return stats, err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return stats, errors.New("this file is not a valid gzip-compressed ServerDeck archive")
	}
	defer gzipReader.Close()
	reader := tar.NewReader(gzipReader)
	foundManifest := false

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return stats, fmt.Errorf("read archive: %w", err)
		}
		stats.Entries++
		if stats.Entries > maxSiteArchiveEntries {
			return stats, errors.New("archive contains too many entries")
		}
		name, err := cleanSiteArchiveName(header.Name)
		if err != nil {
			return stats, err
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return stats, fmt.Errorf("archive entry %q is a link or special file", header.Name)
		}
		if header.Size < 0 || header.Size > maxSiteArchiveBytes-stats.ExpandedSize {
			return stats, errors.New("archive expands beyond the 32 GB safety limit")
		}
		stats.ExpandedSize += header.Size
		if name == "manifest.json" {
			if foundManifest || header.Size > maxManifestBytes {
				return stats, errors.New("archive has an invalid manifest")
			}
			contents, err := io.ReadAll(io.LimitReader(reader, maxManifestBytes+1))
			if err != nil || int64(len(contents)) != header.Size {
				return stats, errors.New("archive manifest is truncated")
			}
			if err := json.Unmarshal(contents, &stats.Manifest); err != nil {
				return stats, errors.New("the archive's manifest could not be read")
			}
			foundManifest = true
		} else if name == "database.sql" && header.Typeflag != tar.TypeDir {
			stats.DatabaseSize += header.Size
		} else if strings.HasPrefix(name, "files"+string(os.PathSeparator)) && header.Typeflag != tar.TypeDir {
			stats.FilesSize += header.Size
		}
	}
	if !foundManifest {
		return stats, errors.New("this file does not look like a ServerDeck site archive")
	}
	// The manifest is an integrity boundary for capacity planning. Permit a small
	// margin for filesystem accounting differences, but never trust a tiny claim
	// attached to a huge payload.
	const allowance = int64(16 * 1024 * 1024)
	if stats.FilesSize > stats.Manifest.FilesBytes+allowance {
		return stats, errors.New("archive files are much larger than its manifest declares")
	}
	if stats.DatabaseSize > stats.Manifest.DatabaseBytes+allowance {
		return stats, errors.New("archive database is much larger than its manifest declares")
	}
	return stats, nil
}

func extractValidatedSiteArchive(path, destination string) (siteArchiveStats, error) {
	stats, err := inspectSiteArchive(path)
	if err != nil {
		return stats, err
	}
	if err := ensureRoomFor(destination, stats.ExpandedSize); err != nil {
		return stats, err
	}

	file, err := os.Open(path)
	if err != nil {
		return stats, err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return stats, err
	}
	defer gzipReader.Close()
	reader := tar.NewReader(gzipReader)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return stats, err
		}
		name, err := cleanSiteArchiveName(header.Name)
		if err != nil {
			return stats, err
		}
		target := filepath.Join(destination, name)
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0755); err != nil {
				return stats, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return stats, err
		}
		mode := os.FileMode(header.Mode) & 0666
		if mode == 0 {
			mode = 0600
		}
		if name == "manifest.json" || name == "database.sql" || name == "vhost.conf" {
			mode = 0600
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return stats, err
		}
		written, copyErr := io.CopyN(output, reader, header.Size)
		closeErr := output.Close()
		if copyErr != nil || written != header.Size {
			return stats, errors.New("archive entry is truncated")
		}
		if closeErr != nil {
			return stats, closeErr
		}
	}
	return stats, nil
}
