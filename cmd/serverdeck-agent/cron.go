package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const managedCronPath = "/etc/cron.d/serverdeck"
const maxCronFileBytes = 4 * 1024 * 1024

type cronJob struct {
	ID       string `json:"id"`
	Schedule string `json:"schedule"`
	User     string `json:"user"`
	Command  string `json:"command"`
	Source   string `json:"source"`
	Line     int    `json:"line"`
	Managed  bool   `json:"managed"`
}

type cronJobRef struct {
	Source string `json:"source"`
	Line   int    `json:"line"`
	Hash   string `json:"hash"`
}

type cronSource struct {
	path       string
	systemWide bool
	user       string
}

var cronFieldPattern = regexp.MustCompile(`^[A-Za-z0-9*/?,#LW-]+$`)
var cronSpecialSchedules = map[string]bool{
	"@reboot": true, "@yearly": true, "@annually": true, "@monthly": true,
	"@weekly": true, "@daily": true, "@midnight": true, "@hourly": true,
}

func listCronJobs() ([]cronJob, error) {
	sources, err := discoverCronSources()
	if err != nil {
		return nil, err
	}
	jobs := []cronJob{}
	for _, source := range sources {
		data, readErr := readCronFile(source)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				continue
			}
			return nil, readErr
		}
		for index, raw := range strings.Split(string(data), "\n") {
			job, ok := parseCronLine(raw, source, index+1)
			if ok {
				jobs = append(jobs, job)
			}
		}
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].Source == jobs[j].Source {
			return jobs[i].Line < jobs[j].Line
		}
		return jobs[i].Source < jobs[j].Source
	})
	return jobs, nil
}

func discoverCronSources() ([]cronSource, error) {
	sources := []cronSource{}
	if regularCronFile("/etc/crontab") {
		sources = append(sources, cronSource{path: "/etc/crontab", systemWide: true})
	}
	entries, err := os.ReadDir("/etc/cron.d")
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, entry := range entries {
		path := filepath.Join("/etc/cron.d", entry.Name())
		if validCronFilename(entry.Name()) && regularCronFile(path) {
			sources = append(sources, cronSource{path: path, systemWide: true})
		}
	}
	entries, err = os.ReadDir("/var/spool/cron/crontabs")
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, entry := range entries {
		path := filepath.Join("/var/spool/cron/crontabs", entry.Name())
		if validCronUser(entry.Name()) && regularCronFile(path) {
			sources = append(sources, cronSource{path: path, user: entry.Name()})
		}
	}
	return sources, nil
}

func regularCronFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func validCronFilename(name string) bool {
	return name != "" && name == filepath.Base(name) && regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(name)
}

func validCronUser(name string) bool {
	return regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`).MatchString(name)
}

func parseCronLine(raw string, source cronSource, line int) (cronJob, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.Contains(strings.Fields(trimmed)[0], "=") {
		return cronJob{}, false
	}
	fields := strings.Fields(trimmed)
	scheduleFields := 5
	if strings.HasPrefix(fields[0], "@") {
		scheduleFields = 1
	}
	required := scheduleFields + 1
	if source.systemWide {
		required++
	}
	if len(fields) < required {
		return cronJob{}, false
	}
	schedule := strings.Join(fields[:scheduleFields], " ")
	if validateCronSchedule(schedule) != nil {
		return cronJob{}, false
	}
	jobUser := source.user
	commandIndex := scheduleFields
	if source.systemWide {
		jobUser = fields[scheduleFields]
		commandIndex++
	}
	command := strings.Join(fields[commandIndex:], " ")
	if !validCronUser(jobUser) || validateCronCommand(command) != nil {
		return cronJob{}, false
	}
	ref := cronJobRef{Source: source.path, Line: line, Hash: cronLineHash(raw)}
	encoded, _ := json.Marshal(ref)
	return cronJob{
		ID: base64.RawURLEncoding.EncodeToString(encoded), Schedule: schedule, User: jobUser,
		Command: command, Source: source.path, Line: line, Managed: source.path == managedCronPath,
	}, true
}

func validateCronSchedule(schedule string) error {
	schedule = strings.TrimSpace(schedule)
	if cronSpecialSchedules[schedule] {
		return nil
	}
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return errors.New("a cron schedule must contain five fields or a supported @ schedule")
	}
	for _, field := range fields {
		if len(field) > 64 || !cronFieldPattern.MatchString(field) {
			return errors.New("the cron schedule contains an invalid field")
		}
	}
	return nil
}

func validateCronCommand(command string) error {
	if strings.TrimSpace(command) == "" || len(command) > 8192 || strings.ContainsAny(command, "\r\n\x00") {
		return errors.New("the cron command is empty, too long, or contains a line break")
	}
	return nil
}

func validateCronUser(name string) error {
	if !validCronUser(name) {
		return errors.New("invalid cron user")
	}
	if _, err := user.Lookup(name); err != nil {
		return errors.New("cron user does not exist")
	}
	return nil
}

func addCronJob(schedule, username, command string) (cronJob, error) {
	if os.Geteuid() != 0 {
		return cronJob{}, errors.New("cron-add must run as root")
	}
	if err := validateCronSchedule(schedule); err != nil {
		return cronJob{}, err
	}
	if err := validateCronUser(username); err != nil {
		return cronJob{}, err
	}
	if err := validateCronCommand(command); err != nil {
		return cronJob{}, err
	}
	line := formatCronLine(schedule, username, command, true)
	data, err := readCronFile(cronSource{path: managedCronPath, systemWide: true})
	if err != nil && !os.IsNotExist(err) {
		return cronJob{}, err
	}
	if len(data) == 0 {
		data = []byte("# Managed by ServerDeck. Changes made here appear in the Cron section.\n")
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, []byte(line+"\n")...)
	if err := writeCronFile(managedCronPath, data); err != nil {
		return cronJob{}, err
	}
	jobs, err := listCronJobs()
	if err != nil {
		return cronJob{}, err
	}
	for i := len(jobs) - 1; i >= 0; i-- {
		if jobs[i].Source == managedCronPath && jobs[i].Schedule == schedule && jobs[i].User == username && jobs[i].Command == command {
			_ = writeAudit("cron.add", true, username+" "+schedule)
			return jobs[i], nil
		}
	}
	return cronJob{}, errors.New("the cron job was written but could not be read back")
}

func updateCronJob(id, schedule, username, command string) (cronJob, error) {
	if os.Geteuid() != 0 {
		return cronJob{}, errors.New("cron-update must run as root")
	}
	if err := validateCronSchedule(schedule); err != nil {
		return cronJob{}, err
	}
	if err := validateCronUser(username); err != nil {
		return cronJob{}, err
	}
	if err := validateCronCommand(command); err != nil {
		return cronJob{}, err
	}
	ref, source, lines, err := resolveCronJob(id)
	if err != nil {
		return cronJob{}, err
	}
	if !source.systemWide && username != source.user {
		return cronJob{}, errors.New("a user crontab job cannot be moved to another user; add a new job instead")
	}
	lines[ref.Line-1] = formatCronLine(schedule, username, command, source.systemWide)
	if err := writeCronFile(source.path, []byte(strings.Join(lines, "\n"))); err != nil {
		return cronJob{}, err
	}
	job, ok := parseCronLine(lines[ref.Line-1], source, ref.Line)
	if !ok {
		return cronJob{}, errors.New("the updated cron job could not be parsed")
	}
	_ = writeAudit("cron.update", true, source.path+":"+strconv.Itoa(ref.Line))
	return job, nil
}

func deleteCronJob(id string) (map[string]bool, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("cron-delete must run as root")
	}
	ref, source, lines, err := resolveCronJob(id)
	if err != nil {
		return nil, err
	}
	lines = append(lines[:ref.Line-1], lines[ref.Line:]...)
	if err := writeCronFile(source.path, []byte(strings.Join(lines, "\n"))); err != nil {
		return nil, err
	}
	_ = writeAudit("cron.delete", true, source.path+":"+strconv.Itoa(ref.Line))
	return map[string]bool{"deleted": true}, nil
}

func resolveCronJob(id string) (cronJobRef, cronSource, []string, error) {
	var ref cronJobRef
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || json.Unmarshal(decoded, &ref) != nil {
		return ref, cronSource{}, nil, errors.New("invalid cron job identifier")
	}
	source, err := allowedCronSource(ref.Source)
	if err != nil {
		return ref, source, nil, err
	}
	data, err := readCronFile(source)
	if err != nil {
		return ref, source, nil, err
	}
	lines := strings.Split(string(data), "\n")
	if ref.Line < 1 || ref.Line > len(lines) || cronLineHash(lines[ref.Line-1]) != ref.Hash {
		return ref, source, nil, errors.New("this cron file changed since it was loaded; refresh before editing")
	}
	if _, ok := parseCronLine(lines[ref.Line-1], source, ref.Line); !ok {
		return ref, source, nil, errors.New("the selected cron line is no longer a job")
	}
	return ref, source, lines, nil
}

func allowedCronSource(path string) (cronSource, error) {
	clean := filepath.Clean(path)
	if clean == "/etc/crontab" {
		return cronSource{path: clean, systemWide: true}, nil
	}
	if filepath.Dir(clean) == "/etc/cron.d" && validCronFilename(filepath.Base(clean)) {
		return cronSource{path: clean, systemWide: true}, nil
	}
	if filepath.Dir(clean) == "/var/spool/cron/crontabs" && validCronUser(filepath.Base(clean)) {
		return cronSource{path: clean, user: filepath.Base(clean)}, nil
	}
	return cronSource{}, errors.New("cron source is outside the supported locations")
}

func writeCronFile(path string, data []byte) error {
	if len(data) > maxCronFileBytes {
		return errors.New("cron file exceeds the safe size limit")
	}
	if regularCronFile(path) {
		source, err := allowedCronSource(path)
		if err != nil {
			return err
		}
		root := "/etc"
		if !source.systemWide {
			root = "/var/spool/cron/crontabs"
		}
		return replaceManagedFile(root, path, data)
	}
	if path != managedCronPath {
		return errors.New("refusing to create an unmanaged cron file")
	}
	return atomicWrite(path, data, 0644)
}

func readCronFile(source cronSource) ([]byte, error) {
	root := "/etc"
	if !source.systemWide {
		root = "/var/spool/cron/crontabs"
	}
	data, err := readManagedFile(root, source.path, maxCronFileBytes)
	if err != nil {
		return nil, err
	}
	if len(data) > maxCronFileBytes {
		return nil, errors.New("cron file exceeds the safe size limit")
	}
	return data, nil
}

func formatCronLine(schedule, username, command string, systemWide bool) string {
	if systemWide {
		return fmt.Sprintf("%s %s %s", strings.TrimSpace(schedule), username, strings.TrimSpace(command))
	}
	return fmt.Sprintf("%s %s", strings.TrimSpace(schedule), strings.TrimSpace(command))
}

func cronLineHash(line string) string {
	digest := sha256.Sum256([]byte(line))
	return hex.EncodeToString(digest[:])
}
