package main

import (
	"strings"
	"testing"
)

func TestBuildRunArgumentsValid(t *testing.T) {
	spec := dockerRunSpec{
		Image:   "nginx:latest",
		Name:    "web1",
		Ports:   []dockerPortMap{{Host: 8080, Container: 80, Proto: "tcp"}},
		Env:     []dockerEnvVar{{Key: "TZ", Value: "UTC"}},
		Volumes: []dockerVolumeMount{{Name: "data", Container: "/data"}},
		Restart: "unless-stopped",
	}
	args, dirs, err := buildRunArguments(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"run -d --name web1", "--restart unless-stopped", "-p 8080:80/tcp", "-e TZ=UTC", "nginx:latest"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %s", want, joined)
		}
	}
	if len(dirs) != 1 || !strings.HasPrefix(dirs[0], dockerVolumeRoot+"/web1/") {
		t.Errorf("volume dir not confined to managed root: %v", dirs)
	}
	// The managed host path, not the caller's, must be what gets mounted.
	if !strings.Contains(joined, dockerVolumeRoot+"/web1/data:/data") {
		t.Errorf("bind mount not rewritten to managed dir: %s", joined)
	}
}

func TestBuildRunArgumentsRejectsBadInput(t *testing.T) {
	cases := map[string]dockerRunSpec{
		"arbitrary host mount": {Image: "nginx", Name: "a", Volumes: []dockerVolumeMount{{Name: "x", Container: "/etc"}, {Name: "../../etc", Container: "/data"}}},
		"path traversal":       {Image: "nginx", Name: "a", Volumes: []dockerVolumeMount{{Name: "ok", Container: "/data/../../etc"}}},
		"host network":         {Image: "nginx", Name: "a", Network: "host"},
		"bad image":            {Image: "-v/etc:/etc", Name: "a"},
		"flag as name":         {Image: "nginx", Name: "--privileged"},
		"bad restart":          {Image: "nginx", Name: "a", Restart: "no-such"},
		"bad env name":         {Image: "nginx", Name: "a", Env: []dockerEnvVar{{Key: "BAD NAME", Value: "x"}}},
		"port range":           {Image: "nginx", Name: "a", Ports: []dockerPortMap{{Host: 0, Container: 80}}},
		"bad proto":            {Image: "nginx", Name: "a", Ports: []dockerPortMap{{Host: 8080, Container: 80, Proto: "sctp"}}},
	}
	for label, spec := range cases {
		if _, _, err := buildRunArguments(spec); err == nil {
			t.Errorf("expected %q to be rejected", label)
		}
	}
}

func TestBuildRunArgumentsNeverGrantsPrivilege(t *testing.T) {
	// Even if a caller tries to smuggle dangerous values, the output vector must
	// never contain privilege/host-escape flags.
	spec := dockerRunSpec{Image: "nginx:latest", Name: "safe", Env: []dockerEnvVar{{Key: "X", Value: "--privileged"}}}
	args, _, err := buildRunArguments(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, forbidden := range []string{"--privileged", "--cap-add", "--net=host", "--pid", "--security-opt"} {
		for _, arg := range args {
			if arg == forbidden {
				t.Errorf("argument vector contains forbidden flag %q", forbidden)
			}
		}
	}
}

func TestDockerCatalogEntriesAreReviewed(t *testing.T) {
	seen := map[string]bool{}
	for _, entry := range dockerCatalogEntries() {
		if entry.ID == "" || entry.Image == "" {
			t.Errorf("catalog entry missing id or image: %+v", entry)
		}
		if seen[entry.ID] {
			t.Errorf("duplicate catalog id %q", entry.ID)
		}
		seen[entry.ID] = true
		if !imageRefPattern.MatchString(entry.Image) {
			t.Errorf("catalog image %q is not a valid reference", entry.Image)
		}
		if _, _, err := buildRunArguments(dockerRunSpec{Image: entry.Image, Name: entry.ID, Ports: entry.Ports, Env: entry.Env, Volumes: entry.Volumes, Restart: "unless-stopped"}); err != nil {
			t.Errorf("catalog app %q does not produce a valid run spec: %v", entry.ID, err)
		}
	}
}
