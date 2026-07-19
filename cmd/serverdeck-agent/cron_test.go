package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestParseSystemAndUserCronLines(t *testing.T) {
	system, ok := parseCronLine("*/5 * * * * www-data /usr/bin/php /srv/task.php", cronSource{path: "/etc/cron.d/app", systemWide: true}, 3)
	if !ok || system.Schedule != "*/5 * * * *" || system.User != "www-data" || system.Command != "/usr/bin/php /srv/task.php" {
		t.Fatalf("unexpected system job: %#v", system)
	}
	userJob, ok := parseCronLine("@reboot /usr/local/bin/start-worker", cronSource{path: "/var/spool/cron/crontabs/alice", user: "alice"}, 2)
	if !ok || userJob.Schedule != "@reboot" || userJob.User != "alice" {
		t.Fatalf("unexpected user job: %#v", userJob)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(system.ID)
	if err != nil {
		t.Fatal(err)
	}
	var ref cronJobRef
	if err := json.Unmarshal(decoded, &ref); err != nil || ref.Source != system.Source || ref.Line != 3 {
		t.Fatalf("unexpected job reference: %#v (%v)", ref, err)
	}
}

func TestCronValidationRejectsUnsafeInput(t *testing.T) {
	for _, schedule := range []string{"", "* * * *", "@sometimes", "* * * * *\n@reboot"} {
		if validateCronSchedule(schedule) == nil {
			t.Errorf("accepted invalid schedule %q", schedule)
		}
	}
	for _, command := range []string{"", "echo ok\nrm -rf /", "echo\x00bad"} {
		if validateCronCommand(command) == nil {
			t.Errorf("accepted invalid command %q", command)
		}
	}
	if _, ok := parseCronLine("PATH=/usr/bin", cronSource{path: "/etc/crontab", systemWide: true}, 1); ok {
		t.Fatal("environment assignment must not be shown as a cron job")
	}
}

func TestFormatCronLine(t *testing.T) {
	if got := formatCronLine("0 2 * * *", "root", "/usr/local/bin/backup", true); got != "0 2 * * * root /usr/local/bin/backup" {
		t.Fatalf("unexpected system line: %q", got)
	}
	if got := formatCronLine("@daily", "alice", "/home/alice/task", false); got != "@daily /home/alice/task" {
		t.Fatalf("unexpected user line: %q", got)
	}
}
