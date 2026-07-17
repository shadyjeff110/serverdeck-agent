package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Docker management: curated one-click catalog plus a guardrailed manual mode
// (pull/list/remove images, run/remove containers, compose projects, and
// publishing a container behind a managed reverse-proxy domain).
//
// Guardrails (manual container run): validated inputs, no --privileged, no host
// networking, and bind mounts confined to a managed data directory under
// /var/lib/serverdeck/docker/<container>/ — never arbitrary host paths.
// Compose is the explicit advanced escape hatch: its YAML is author-controlled
// and only confined to a managed project directory, not otherwise restricted.

const (
	dockerVolumeRoot  = "/var/lib/serverdeck/docker"
	dockerComposeRoot = "/var/lib/serverdeck/compose"
)

var (
	imageRefPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,255}$`)
	envKeyPattern        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	volumeNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	containerPathPattern = regexp.MustCompile(`^/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`)
	dockerNetworkPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	composeNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	validRestartPolicies = map[string]bool{"no": true, "on-failure": true, "unless-stopped": true, "always": true}
)

type dockerImage struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	ID         string `json:"id"`
	Size       string `json:"size"`
	Created    string `json:"created"`
}

type dockerImageInventory struct {
	Installed bool          `json:"installed"`
	Active    bool          `json:"active"`
	Images    []dockerImage `json:"images"`
}

type dockerPortMap struct {
	Host      int    `json:"host"`
	Container int    `json:"container"`
	Proto     string `json:"proto"`
}

type dockerEnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type dockerVolumeMount struct {
	Name      string `json:"name"`
	Container string `json:"container"`
	ReadOnly  bool   `json:"readOnly"`
}

type dockerRunSpec struct {
	Image   string              `json:"image"`
	Name    string              `json:"name"`
	Ports   []dockerPortMap     `json:"ports"`
	Env     []dockerEnvVar      `json:"env"`
	Volumes []dockerVolumeMount `json:"volumes"`
	Restart string              `json:"restart"`
	Network string              `json:"network"`
}

func dockerReady() (bool, bool) {
	return packageVersion("docker.io") != "", unitActive("docker")
}

func listImages() (dockerImageInventory, error) {
	installed, active := dockerReady()
	result := dockerImageInventory{Installed: installed, Active: active, Images: []dockerImage{}}
	if !installed || !active {
		return result, nil
	}
	output, err := exec.Command("docker", "images", "--format", "{{json .}}").CombinedOutput()
	if err != nil {
		return result, fmt.Errorf("list images: %s", tail(string(output), 800))
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var raw map[string]string
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return result, fmt.Errorf("decode image inventory: %w", err)
		}
		result.Images = append(result.Images, dockerImage{
			Repository: raw["Repository"], Tag: raw["Tag"], ID: raw["ID"],
			Size: raw["Size"], Created: raw["CreatedSince"],
		})
	}
	sort.Slice(result.Images, func(i, j int) bool {
		if result.Images[i].Repository == result.Images[j].Repository {
			return result.Images[i].Tag < result.Images[j].Tag
		}
		return result.Images[i].Repository < result.Images[j].Repository
	})
	return result, nil
}

func pullImage(ref string) (dockerImageInventory, error) {
	if os.Geteuid() != 0 {
		return dockerImageInventory{}, errors.New("image-pull must run as root")
	}
	ref = strings.TrimSpace(ref)
	if !imageRefPattern.MatchString(ref) {
		return dockerImageInventory{}, errors.New("invalid image reference")
	}
	emitProgress("pull", "running", "Pulling "+ref)
	if output, err := runProgressCommand("docker", "pull", ref); err != nil {
		_ = writeAudit("docker.image.pull.failed", false, ref+": "+tail(string(output), 400))
		return dockerImageInventory{}, fmt.Errorf("pull image: %s", tail(string(output), 800))
	}
	emitProgress("pull", "completed", "Pulled "+ref)
	_ = writeAudit("docker.image.pull", true, ref)
	return listImages()
}

func removeImage(ref string) (dockerImageInventory, error) {
	if os.Geteuid() != 0 {
		return dockerImageInventory{}, errors.New("image-remove must run as root")
	}
	ref = strings.TrimSpace(ref)
	if !imageRefPattern.MatchString(ref) {
		return dockerImageInventory{}, errors.New("invalid image reference")
	}
	if output, err := exec.Command("docker", "rmi", "--", ref).CombinedOutput(); err != nil {
		return dockerImageInventory{}, fmt.Errorf("remove image: %s", tail(string(output), 800))
	}
	_ = writeAudit("docker.image.remove", true, ref)
	return listImages()
}

// buildRunArguments validates a run spec and returns the argument vector for
// `docker run`. It never emits --privileged, host networking, or capability
// grants, and every bind mount is rewritten to a managed host directory.
func buildRunArguments(spec dockerRunSpec) ([]string, []string, error) {
	spec.Image = strings.TrimSpace(spec.Image)
	spec.Name = strings.TrimSpace(spec.Name)
	if !imageRefPattern.MatchString(spec.Image) {
		return nil, nil, errors.New("invalid image reference")
	}
	if !containerNamePattern.MatchString(spec.Name) {
		return nil, nil, errors.New("invalid container name")
	}
	if spec.Restart == "" {
		spec.Restart = "unless-stopped"
	}
	if !validRestartPolicies[spec.Restart] {
		return nil, nil, errors.New("unsupported restart policy")
	}
	args := []string{"run", "-d", "--name", spec.Name, "--restart", spec.Restart}

	seenHostPorts := map[int]bool{}
	for _, port := range spec.Ports {
		if port.Container < 1 || port.Container > 65535 || port.Host < 1 || port.Host > 65535 {
			return nil, nil, errors.New("port numbers must be between 1 and 65535")
		}
		proto := port.Proto
		if proto == "" {
			proto = "tcp"
		}
		if proto != "tcp" && proto != "udp" {
			return nil, nil, errors.New("port protocol must be tcp or udp")
		}
		if seenHostPorts[port.Host] {
			return nil, nil, fmt.Errorf("host port %d is mapped more than once", port.Host)
		}
		seenHostPorts[port.Host] = true
		args = append(args, "-p", fmt.Sprintf("%d:%d/%s", port.Host, port.Container, proto))
	}

	for _, env := range spec.Env {
		if !envKeyPattern.MatchString(env.Key) {
			return nil, nil, fmt.Errorf("invalid environment variable name %q", env.Key)
		}
		if strings.ContainsAny(env.Value, "\n\r") || len(env.Value) > 4096 {
			return nil, nil, fmt.Errorf("invalid value for environment variable %q", env.Key)
		}
		args = append(args, "-e", env.Key+"="+env.Value)
	}

	createdDirs := []string{}
	for _, volume := range spec.Volumes {
		if !volumeNamePattern.MatchString(volume.Name) {
			return nil, nil, errors.New("invalid volume name")
		}
		if !containerPathPattern.MatchString(volume.Container) || strings.Contains(volume.Container, "..") {
			return nil, nil, errors.New("invalid container mount path")
		}
		hostDir := filepath.Join(dockerVolumeRoot, spec.Name, volume.Name)
		createdDirs = append(createdDirs, hostDir)
		mount := hostDir + ":" + volume.Container
		if volume.ReadOnly {
			mount += ":ro"
		}
		args = append(args, "-v", mount)
	}

	if spec.Network != "" {
		if spec.Network == "host" || spec.Network == "none" {
			return nil, nil, errors.New("host and none networks are not permitted")
		}
		if !dockerNetworkPattern.MatchString(spec.Network) {
			return nil, nil, errors.New("invalid network name")
		}
		args = append(args, "--network", spec.Network)
	}

	args = append(args, spec.Image)
	return args, createdDirs, nil
}

func ensureNetwork(name string) error {
	if name == "" {
		return nil
	}
	if err := exec.Command("docker", "network", "inspect", "--", name).Run(); err == nil {
		return nil
	}
	if output, err := exec.Command("docker", "network", "create", "--", name).CombinedOutput(); err != nil {
		return fmt.Errorf("create network %s: %s", name, tail(string(output), 400))
	}
	return nil
}

func createContainer(specJSON string) (containerInventory, error) {
	if os.Geteuid() != 0 {
		return containerInventory{}, errors.New("container-create must run as root")
	}
	var spec dockerRunSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return containerInventory{}, fmt.Errorf("decode container spec: %w", err)
	}
	if installed, active := dockerReady(); !installed || !active {
		return containerInventory{}, errors.New("Docker must be installed and running")
	}
	args, dirs, err := buildRunArguments(spec)
	if err != nil {
		return containerInventory{}, err
	}
	if err := ensureNetwork(spec.Network); err != nil {
		return containerInventory{}, err
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return containerInventory{}, fmt.Errorf("create volume directory: %w", err)
		}
	}
	if output, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		_ = writeAudit("docker.container.create.failed", false, spec.Name+": "+tail(string(output), 400))
		return containerInventory{}, fmt.Errorf("create container: %s", tail(string(output), 800))
	}
	_ = writeAudit("docker.container.create", true, spec.Name+" ("+spec.Image+")")
	return inspectContainers()
}

func removeContainer(name string) (containerInventory, error) {
	if os.Geteuid() != 0 {
		return containerInventory{}, errors.New("container-remove must run as root")
	}
	name = strings.TrimSpace(name)
	if !containerNamePattern.MatchString(name) {
		return containerInventory{}, errors.New("invalid container name")
	}
	if output, err := exec.Command("docker", "rm", "-f", "--", name).CombinedOutput(); err != nil {
		return containerInventory{}, fmt.Errorf("remove container: %s", tail(string(output), 800))
	}
	_ = writeAudit("docker.container.remove", true, name)
	return inspectContainers()
}

// publishContainer creates a managed reverse-proxy website that forwards a
// domain to a container's published host port on 127.0.0.1. The resulting site
// participates in the normal Domains/TLS flow (its Kind is "proxy").
func publishContainer(domain string, hostPort int) (site, error) {
	value := site{}
	if os.Geteuid() != 0 {
		return value, errors.New("container-publish must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if len(domain) > 253 || !domainPattern.MatchString(domain) {
		return value, errors.New("invalid domain name")
	}
	if hostPort < 1 || hostPort > 65535 {
		return value, errors.New("host port must be between 1 and 65535")
	}
	webServer := ""
	if packageVersion("nginx") != "" && unitActive("nginx") {
		webServer = "nginx"
	} else if packageVersion("apache2") != "" && unitActive("apache2") {
		webServer = "apache"
	} else {
		return value, errors.New("Nginx or Apache must be installed and running")
	}
	configPath := filepath.Join("/etc/nginx/sites-available", domain)
	enabledPath := filepath.Join("/etc/nginx/sites-enabled", domain)
	if webServer == "apache" {
		configPath = filepath.Join("/etc/apache2/sites-available", domain+".conf")
		enabledPath = filepath.Join("/etc/apache2/sites-enabled", domain+".conf")
	}
	metadataPath := filepath.Join("/var/lib/serverdeck/sites", domain+".json")
	for _, path := range []string{configPath, enabledPath, metadataPath} {
		if _, err := os.Lstat(path); err == nil {
			return value, errors.New("a managed site with this domain already exists")
		}
	}
	config := fmt.Sprintf("server {\n    listen 80;\n    listen [::]:80;\n    server_name %s;\n    location / {\n        proxy_pass http://127.0.0.1:%d;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n}\n", domain, hostPort)
	if webServer == "apache" {
		if output, err := exec.Command("a2enmod", "proxy", "proxy_http", "headers").CombinedOutput(); err != nil {
			return value, fmt.Errorf("enable Apache proxy modules: %s", tail(string(output), 800))
		}
		config = fmt.Sprintf("<VirtualHost *:80>\n    ServerName %s\n    ProxyPreserveHost On\n    ProxyPass / http://127.0.0.1:%d/\n    ProxyPassReverse / http://127.0.0.1:%d/\n    RequestHeader set X-Forwarded-Proto expr=%%{REQUEST_SCHEME}\n</VirtualHost>\n", domain, hostPort, hostPort)
	}
	if err := atomicWrite(configPath, []byte(config), 0644); err != nil {
		return value, err
	}
	if webServer == "nginx" {
		if err := os.Symlink(configPath, enabledPath); err != nil {
			_ = os.Remove(configPath)
			return value, err
		}
	} else if output, err := exec.Command("a2ensite", domain+".conf").CombinedOutput(); err != nil {
		_ = os.Remove(configPath)
		return value, fmt.Errorf("enable Apache site: %s", tail(string(output), 800))
	}
	rollback := func() {
		_ = os.Remove(enabledPath)
		_ = os.Remove(configPath)
		_ = exec.Command("systemctl", "reload", map[string]string{"nginx": "nginx", "apache": "apache2"}[webServer]).Run()
	}
	validation := exec.Command("nginx", "-t")
	if webServer == "apache" {
		validation = exec.Command("apache2ctl", "configtest")
	}
	if output, err := validation.CombinedOutput(); err != nil {
		rollback()
		return value, fmt.Errorf("%s validation failed: %s", webServer, tail(string(output), 800))
	}
	if err := exec.Command("systemctl", "reload", map[string]string{"nginx": "nginx", "apache": "apache2"}[webServer]).Run(); err != nil {
		rollback()
		return value, err
	}
	value = site{Domain: domain, Kind: "proxy", Enabled: true, Port: hostPort, CreatedAt: time.Now().UTC().Format(time.RFC3339), WebServer: webServer}
	encoded, _ := json.MarshalIndent(value, "", "  ")
	if err := atomicWrite(metadataPath, append(encoded, '\n'), 0644); err != nil {
		return site{}, err
	}
	_ = writeAudit("docker.container.publish", true, fmt.Sprintf("%s -> 127.0.0.1:%d", domain, hostPort))
	return value, nil
}

// --- Curated catalog ---

type dockerCatalogEntry struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Category       string              `json:"category"`
	Description    string              `json:"description"`
	Image          string              `json:"image"`
	WebPort        int                 `json:"webPort"` // container port to reverse-proxy for a domain (0 = not web)
	Ports          []dockerPortMap     `json:"ports"`
	Volumes        []dockerVolumeMount `json:"volumes"`
	Env            []dockerEnvVar      `json:"env"`
	SupportsDomain bool                `json:"supportsDomain"`
}

// dockerCatalogEntries is the reviewed one-click catalog. Images are official
// or well-established upstream images pulled from Docker Hub.
func dockerCatalogEntries() []dockerCatalogEntry {
	return []dockerCatalogEntry{
		{ID: "portainer", Name: "Portainer CE", Category: "Management", Description: "Web UI for managing Docker.", Image: "portainer/portainer-ce:latest", WebPort: 9000, SupportsDomain: true,
			Ports:   []dockerPortMap{{Host: 9000, Container: 9000, Proto: "tcp"}},
			Volumes: []dockerVolumeMount{{Name: "data", Container: "/data"}}},
		{ID: "uptimekuma", Name: "Uptime Kuma", Category: "Monitoring", Description: "Self-hosted uptime monitoring.", Image: "louislam/uptime-kuma:1", WebPort: 3001, SupportsDomain: true,
			Ports:   []dockerPortMap{{Host: 3001, Container: 3001, Proto: "tcp"}},
			Volumes: []dockerVolumeMount{{Name: "data", Container: "/app/data"}}},
		{ID: "vaultwarden", Name: "Vaultwarden", Category: "Security", Description: "Bitwarden-compatible password manager.", Image: "vaultwarden/server:latest", WebPort: 80, SupportsDomain: true,
			Ports:   []dockerPortMap{{Host: 8080, Container: 80, Proto: "tcp"}},
			Volumes: []dockerVolumeMount{{Name: "data", Container: "/data"}}},
		{ID: "gitea", Name: "Gitea", Category: "Development", Description: "Lightweight self-hosted Git service.", Image: "gitea/gitea:latest", WebPort: 3000, SupportsDomain: true,
			Ports:   []dockerPortMap{{Host: 3000, Container: 3000, Proto: "tcp"}, {Host: 2222, Container: 22, Proto: "tcp"}},
			Volumes: []dockerVolumeMount{{Name: "data", Container: "/data"}}},
		{ID: "n8n", Name: "n8n", Category: "Automation", Description: "Workflow automation tool.", Image: "n8nio/n8n:latest", WebPort: 5678, SupportsDomain: true,
			Ports:   []dockerPortMap{{Host: 5678, Container: 5678, Proto: "tcp"}},
			Volumes: []dockerVolumeMount{{Name: "data", Container: "/home/node/.n8n"}}},
		{ID: "adminer", Name: "Adminer", Category: "Database", Description: "Database management in a single file.", Image: "adminer:latest", WebPort: 8080, SupportsDomain: true,
			Ports: []dockerPortMap{{Host: 8081, Container: 8080, Proto: "tcp"}}},
	}
}

func dockerCatalog() []dockerCatalogEntry {
	return dockerCatalogEntries()
}

type dockerAppInstallOptions struct {
	Name          string `json:"name"`
	Domain        string `json:"domain"`
	PublishDomain bool   `json:"publishDomain"`
}

type dockerAppInstallResult struct {
	Container string `json:"container"`
	Image     string `json:"image"`
	HostPort  int    `json:"hostPort"`
	Domain    string `json:"domain,omitempty"`
	Published bool   `json:"published"`
	Message   string `json:"message"`
}

func installDockerApp(appID, optionsJSON string) (dockerAppInstallResult, error) {
	result := dockerAppInstallResult{}
	if os.Geteuid() != 0 {
		return result, errors.New("docker-app-install must run as root")
	}
	var options dockerAppInstallOptions
	if err := json.Unmarshal([]byte(optionsJSON), &options); err != nil {
		return result, fmt.Errorf("decode install options: %w", err)
	}
	var entry *dockerCatalogEntry
	for _, candidate := range dockerCatalogEntries() {
		if candidate.ID == appID {
			found := candidate
			entry = &found
			break
		}
	}
	if entry == nil {
		return result, errors.New("unknown catalog app")
	}
	if installed, active := dockerReady(); !installed || !active {
		return result, errors.New("Docker must be installed and running")
	}
	name := strings.TrimSpace(options.Name)
	if name == "" {
		name = entry.ID
	}
	if !containerNamePattern.MatchString(name) {
		return result, errors.New("invalid container name")
	}

	emitProgress("pull", "running", "Pulling "+entry.Image)
	if output, err := runProgressCommand("docker", "pull", entry.Image); err != nil {
		return result, fmt.Errorf("pull image: %s", tail(string(output), 800))
	}

	spec := dockerRunSpec{Image: entry.Image, Name: name, Ports: entry.Ports, Env: entry.Env, Volumes: entry.Volumes, Restart: "unless-stopped"}
	emitProgress("container", "running", "Creating container "+name)
	if _, err := createContainer(mustJSON(spec)); err != nil {
		return result, err
	}
	result.Container = name
	result.Image = entry.Image
	if len(entry.Ports) > 0 {
		result.HostPort = entry.Ports[0].Host
	}
	result.Message = "Container is running."

	if options.PublishDomain && entry.SupportsDomain && strings.TrimSpace(options.Domain) != "" && result.HostPort > 0 {
		emitProgress("domain", "running", "Publishing "+options.Domain)
		if _, err := publishContainer(options.Domain, result.HostPort); err != nil {
			// A domain problem must not fail an install that already succeeded.
			result.Message = "Container is running, but domain publish failed: " + err.Error()
			emitProgress("domain", "failed", err.Error())
		} else {
			result.Domain = strings.ToLower(strings.TrimSpace(options.Domain))
			result.Published = true
			result.Message = "Container is running and published. Issue a certificate from Domains for HTTPS."
			emitProgress("domain", "completed", "Published "+result.Domain)
		}
	}
	_ = writeAudit("docker.app.install", true, entry.ID+" as "+name)
	return result, nil
}

func mustJSON(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

// --- Compose ---

type composeProject struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Running bool   `json:"running"`
}

type composeInventory struct {
	Available bool             `json:"available"`
	Projects  []composeProject `json:"projects"`
}

// composeCommand returns the argument prefix for the available Docker Compose
// implementation (v2 plugin `docker compose`, or the standalone
// `docker-compose`), or ok=false when neither is installed.
func composeCommand() ([]string, bool) {
	if err := exec.Command("docker", "compose", "version").Run(); err == nil {
		return []string{"docker", "compose"}, true
	}
	if _, err := exec.LookPath("docker-compose"); err == nil {
		return []string{"docker-compose"}, true
	}
	return nil, false
}

func runCompose(dir string, stream bool, extra ...string) ([]byte, error) {
	prefix, ok := composeCommand()
	if !ok {
		return nil, errors.New("Docker Compose is not installed on this server")
	}
	args := append(prefix[1:], "-f", filepath.Join(dir, "docker-compose.yml"))
	args = append(args, extra...)
	if stream {
		return runProgressCommand(prefix[0], args...)
	}
	return exec.Command(prefix[0], args...).CombinedOutput()
}

func listComposeProjects() (composeInventory, error) {
	_, available := composeCommand()
	result := composeInventory{Available: available, Projects: []composeProject{}}
	paths, _ := filepath.Glob(filepath.Join(dockerComposeRoot, "*", "docker-compose.yml"))
	for _, path := range paths {
		dir := filepath.Dir(path)
		project := composeProject{Name: filepath.Base(dir), Path: path}
		if available {
			if output, err := runCompose(dir, false, "ps", "-q"); err == nil {
				project.Running = strings.TrimSpace(string(output)) != ""
			}
		}
		result.Projects = append(result.Projects, project)
	}
	sort.Slice(result.Projects, func(i, j int) bool { return result.Projects[i].Name < result.Projects[j].Name })
	return result, nil
}

func composeUp(name, content string) (composeInventory, error) {
	if os.Geteuid() != 0 {
		return composeInventory{}, errors.New("compose-up must run as root")
	}
	name = strings.TrimSpace(name)
	if !composeNamePattern.MatchString(name) {
		return composeInventory{}, errors.New("invalid project name (use lowercase letters, numbers, hyphen, underscore)")
	}
	if len(content) > 512*1024 {
		return composeInventory{}, errors.New("compose file is too large")
	}
	if _, ok := composeCommand(); !ok {
		return composeInventory{}, errors.New("Docker Compose is not installed on this server")
	}
	dir := filepath.Join(dockerComposeRoot, name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return composeInventory{}, err
	}
	if err := atomicWrite(filepath.Join(dir, "docker-compose.yml"), []byte(content), 0644); err != nil {
		return composeInventory{}, err
	}
	emitProgress("compose", "running", "Starting project "+name)
	if output, err := runCompose(dir, true, "up", "-d"); err != nil {
		_ = writeAudit("docker.compose.up.failed", false, name+": "+tail(string(output), 400))
		return composeInventory{}, fmt.Errorf("compose up: %s", tail(string(output), 1000))
	}
	emitProgress("compose", "completed", "Project "+name+" is up")
	_ = writeAudit("docker.compose.up", true, name)
	return listComposeProjects()
}

func composeDown(name string) (composeInventory, error) {
	if os.Geteuid() != 0 {
		return composeInventory{}, errors.New("compose-down must run as root")
	}
	name = strings.TrimSpace(name)
	if !composeNamePattern.MatchString(name) {
		return composeInventory{}, errors.New("invalid project name")
	}
	dir := filepath.Join(dockerComposeRoot, name)
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err != nil {
		return composeInventory{}, errors.New("compose project was not found")
	}
	if output, err := runCompose(dir, false, "down"); err != nil {
		return composeInventory{}, fmt.Errorf("compose down: %s", tail(string(output), 800))
	}
	_ = writeAudit("docker.compose.down", true, name)
	return listComposeProjects()
}

// parsePort is a small helper for decoded string port arguments.
func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("invalid port")
	}
	return port, nil
}
