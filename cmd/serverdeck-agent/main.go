package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	version         = "0.22.0"
	protocolVersion = 1
)

type response struct {
	OK       bool        `json:"ok"`
	Protocol int         `json:"protocol"`
	Version  string      `json:"version"`
	Data     interface{} `json:"data,omitempty"`
	Error    string      `json:"error,omitempty"`
}

type service struct {
	Name        string `json:"name"`
	Installed   bool   `json:"installed"`
	Active      bool   `json:"active"`
	Description string `json:"description"`
}

type site struct {
	Domain      string `json:"domain"`
	Kind        string `json:"kind"`
	Root        string `json:"root"`
	Enabled     bool   `json:"enabled"`
	PHPVersion  string `json:"php_version,omitempty"`
	CreatedAt   string `json:"created_at"`
	NodeVersion string `json:"node_version,omitempty"`
	Service     string `json:"service,omitempty"`
	Port        int    `json:"port,omitempty"`
	WebServer   string `json:"web_server,omitempty"`
}

type phpRuntime struct {
	Version string `json:"version"`
	Socket  string `json:"socket"`
	Active  bool   `json:"active"`
}

type runtimes struct {
	PHP  []phpRuntime `json:"php"`
	Node []string     `json:"node"`
}

type softwarePackage struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Package     string `json:"package"`
	Installed   bool   `json:"installed"`
	Version     string `json:"version,omitempty"`
	Candidate   string `json:"candidate,omitempty"`
	Active      bool   `json:"active"`
	Description string `json:"description"`
}

type packageSource struct {
	ID        string `json:"id"`
	File      string `json:"file"`
	URI       string `json:"uri"`
	Suite     string `json:"suite,omitempty"`
	Official  bool   `json:"official"`
	SignedBy  string `json:"signed_by,omitempty"`
	Enabled   bool   `json:"enabled"`
}

type sourceCatalogItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Supported   bool   `json:"supported"`
	Enabled     bool   `json:"enabled"`
	Reason      string `json:"reason,omitempty"`
}

type softwareRemovalPlan struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Allowed  bool     `json:"allowed"`
	Reason   string   `json:"reason"`
	Affected []string `json:"affected"`
}

type webMigrationPlan struct {
	Source       string   `json:"source"`
	Target       string   `json:"target"`
	Sites        []string `json:"sites"`
	TLS          []string `json:"tls"`
	SafetyBackup bool     `json:"safety_backup"`
	Allowed      bool     `json:"allowed"`
	Reason       string   `json:"reason"`
}

type phpVersionStatus struct {
	Version    string   `json:"version"`
	Installed  bool     `json:"installed"`
	Active     bool     `json:"active"`
	Available  bool     `json:"available"`
	Extensions []string `json:"extensions"`
	UsedBy     []string `json:"used_by"`
}

type mailStatus struct {
	Hostname         string `json:"hostname"`
	PostfixInstalled bool   `json:"postfix_installed"`
	PostfixActive    bool   `json:"postfix_active"`
	DovecotInstalled bool   `json:"dovecot_installed"`
	DovecotActive    bool   `json:"dovecot_active"`
	Mailname         string `json:"mailname,omitempty"`
	ReadyForSetup    bool   `json:"ready_for_setup"`
}

type dkimMaterial struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
	Name     string `json:"name"`
	Value    string `json:"value"`
}

type mailTLSStatus struct {
	Domain      string `json:"domain"`
	Hostname    string `json:"hostname"`
	Certificate bool   `json:"certificate"`
	PostfixTLS  bool   `json:"postfix_tls"`
	DovecotTLS  bool   `json:"dovecot_tls"`
}

type dnsRequirement struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Value   string `json:"value"`
	Present bool   `json:"present"`
	Note    string `json:"note"`
}

type mailDNSCheck struct {
	Domain  string           `json:"domain"`
	Records []dnsRequirement `json:"records"`
}

type managedFile struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Directory bool   `json:"directory"`
	Size      int64  `json:"size"`
	Modified  string `json:"modified"`
}

type fileContents struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type containerStatus struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Ports   string `json:"ports"`
	Created string `json:"created"`
}

type containerInventory struct {
	Installed  bool              `json:"installed"`
	Active     bool              `json:"active"`
	Version    string            `json:"version,omitempty"`
	Containers []containerStatus `json:"containers"`
}

type containerLogs struct {
	Container string `json:"container"`
	Lines     string `json:"lines"`
}

type database struct {
	Name      string `json:"name"`
	Username  string `json:"username"`
	Host      string `json:"host"`
	CreatedAt string `json:"created_at"`
	Password  string `json:"password,omitempty"`
	Engine    string `json:"engine,omitempty"`
}

type tlsStatus struct {
	Domain       string   `json:"domain"`
	DNSAddresses []string `json:"dns_addresses"`
	ServerIPs    []string `json:"server_ips"`
	Ready        bool     `json:"ready"`
	Certificate  bool     `json:"certificate"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	Message      string   `json:"message"`
}

type backup struct {
	ID        string   `json:"id"`
	CreatedAt string   `json:"created_at"`
	Archive   string   `json:"archive"`
	Size      int64    `json:"size"`
	SHA256    string   `json:"sha256"`
	Sites     []string `json:"sites"`
	Databases []string `json:"databases"`
	Verified  bool     `json:"verified"`
}

type restorePreview struct {
	Backup           backup   `json:"backup"`
	ConflictingSites []string `json:"conflicting_sites"`
	ConflictingDBs   []string `json:"conflicting_databases"`
}

type restoreResult struct {
	RestoredBackupID string `json:"restored_backup_id"`
	SafetyBackupID   string `json:"safety_backup_id"`
	Sites            int    `json:"sites"`
	Databases        int    `json:"databases"`
}

type backupPolicy struct {
	Enabled   bool   `json:"enabled"`
	Hour      int    `json:"hour"`
	Retention int    `json:"retention"`
	Timer     string `json:"timer"`
}

type monitoringStatus struct {
	Load1       float64  `json:"load_1"`
	Load5       float64  `json:"load_5"`
	Load15      float64  `json:"load_15"`
	FailedUnits []string `json:"failed_units"`
	Running     int      `json:"running_services"`
	CheckedAt   string   `json:"checked_at"`
}

type serviceLogs struct {
	Service string `json:"service"`
	Lines   string `json:"lines"`
}

type securityStatus struct {
	FirewallActive         bool     `json:"firewall_active"`
	FirewallRules          []string `json:"firewall_rules"`
	Fail2banInstalled      bool     `json:"fail2ban_installed"`
	Fail2banActive         bool     `json:"fail2ban_active"`
	PermitRootLogin        string   `json:"permit_root_login"`
	PasswordAuthentication string   `json:"password_authentication"`
	PubkeyAuthentication   string   `json:"pubkey_authentication"`
	UpdatesAvailable       int      `json:"updates_available"`
	Findings               []string `json:"findings"`
}

type updatePackage struct {
	Name      string `json:"name"`
	Current   string `json:"current"`
	Candidate string `json:"candidate"`
}

type updateResult struct {
	Updated        int    `json:"updated"`
	SafetyBackupID string `json:"safety_backup_id"`
	RebootRequired bool   `json:"reboot_required"`
	Summary        string `json:"summary"`
}

var databaseNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

var managedServices = map[string]string{
	"nginx":      "Web server",
	"apache2":    "Web server",
	"mariadb":    "MariaDB database",
	"mysql":      "MySQL database",
	"postgresql": "PostgreSQL database",
	"postfix":    "Mail transport",
	"dovecot":    "Mail delivery",
	"docker":     "Container runtime",
	"redis-server": "Cache and data store",
	"vsftpd":     "Legacy FTP server",
	"fail2ban":   "Intrusion prevention",
	"ufw":        "Firewall",
}

var webStackPackages = []string{
	"nginx",
	"mariadb-server",
	"php-fpm",
	"php-cli",
	"php-mysql",
	"certbot",
	"python3-certbot-nginx",
}

func main() {
	command := "status"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	var data interface{}
	var err error
	switch command {
	case "version":
		fmt.Println(version)
		return
	case "status":
		data = map[string]interface{}{
			"agent_version":    version,
			"protocol_version": protocolVersion,
			"go_version":       runtime.Version(),
			"architecture":     runtime.GOARCH,
			"timestamp":        time.Now().UTC().Format(time.RFC3339),
		}
	case "services":
		data, err = inspectServices()
	case "public-address":
		data, err = detectPublicAddress()
	case "stack-plan":
		data = map[string]interface{}{
			"name":     "web",
			"packages": webStackPackages,
			"changes": []string{
				"Install the managed web stack using Ubuntu packages",
				"Enable Nginx, MariaDB, and the default PHP-FPM service",
				"Do not create websites, databases, or certificates yet",
			},
		}
	case "stack-install":
		if len(os.Args) != 11 {
			err = errors.New("stack-install requires hosting, security, and SSH port choices")
			break
		}
		var php, node, redis, ftp, fail2ban, firewall bool
		var sshPort int
		php, err = strconv.ParseBool(os.Args[4])
		if err == nil { node, err = strconv.ParseBool(os.Args[5]) }
		if err == nil { redis, err = strconv.ParseBool(os.Args[6]) }
		if err == nil { ftp, err = strconv.ParseBool(os.Args[7]) }
		if err == nil { fail2ban, err = strconv.ParseBool(os.Args[8]) }
		if err == nil { firewall, err = strconv.ParseBool(os.Args[9]) }
		if err == nil { sshPort, err = strconv.Atoi(os.Args[10]) }
		if err == nil { data, err = installWebStack(os.Args[2], os.Args[3], php, node, redis, ftp, fail2ban, firewall, sshPort) }
	case "site-list":
		data, err = listSites()
	case "site-create":
		if len(os.Args) != 4 {
			err = errors.New("site-create requires an encoded domain and site kind")
			break
		}
		var decoded []byte
		decoded, err = base64.RawURLEncoding.DecodeString(os.Args[2])
		if err == nil {
			data, err = createSite(string(decoded), os.Args[3])
		}
	case "runtime-list":
		data, err = listRuntimes()
	case "software-list":
		data, err = listSoftware()
	case "source-list":
		data, err = listPackageSources()
	case "source-catalog":
		data, err = packageSourceCatalog()
	case "source-enable":
		if len(os.Args) != 3 {
			err = errors.New("source-enable requires an encoded catalog ID")
			break
		}
		sourceID, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = enablePackageSource(sourceID)
	case "software-install":
		if len(os.Args) != 3 {
			err = errors.New("software-install requires an encoded catalog ID")
			break
		}
		softwareID, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = installCatalogSoftware(softwareID)
	case "software-remove-plan":
		if len(os.Args) != 3 {
			err = errors.New("software-remove-plan requires an encoded catalog ID")
			break
		}
		softwareID, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = planSoftwareRemoval(softwareID)
	case "software-remove":
		if len(os.Args) != 3 {
			err = errors.New("software-remove requires an encoded catalog ID")
			break
		}
		softwareID, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = removeCatalogSoftware(softwareID)
	case "web-migration-plan":
		if len(os.Args) != 3 {
			err = errors.New("web-migration-plan requires a target web server")
			break
		}
		data, err = planWebMigration(os.Args[2])
	case "web-migrate":
		if len(os.Args) != 3 {
			err = errors.New("web-migrate requires a target web server")
			break
		}
		data, err = migrateWebServer(os.Args[2])
	case "mail-status":
		data, err = inspectMail()
	case "mail-stack-install":
		data, err = installMailStack()
	case "mail-dkim-prepare":
		if len(os.Args) != 3 {
			err = errors.New("mail-dkim-prepare requires an encoded domain")
			break
		}
		decodedDomain, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = prepareDKIM(decodedDomain)
	case "mail-tls-issue":
		if len(os.Args) != 4 {
			err = errors.New("mail-tls-issue requires an encoded domain and email")
			break
		}
		tlsDomain, domainErr := decodeArgument(os.Args[2])
		tlsEmail, emailErr := decodeArgument(os.Args[3])
		if domainErr != nil {
			err = domainErr
			break
		}
		if emailErr != nil {
			err = emailErr
			break
		}
		data, err = issueMailTLS(tlsDomain, tlsEmail)
	case "mail-dns-check":
		if len(os.Args) != 3 {
			err = errors.New("mail-dns-check requires an encoded domain")
			break
		}
		checkDomain, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = checkMailDNS(checkDomain)
	case "file-list":
		if len(os.Args) != 4 {
			err = errors.New("file-list requires an encoded domain and path")
			break
		}
		data, err = listManagedFilesEncoded(os.Args[2], os.Args[3])
	case "file-read":
		if len(os.Args) != 4 {
			err = errors.New("file-read requires an encoded domain and path")
			break
		}
		data, err = readManagedFileEncoded(os.Args[2], os.Args[3])
	case "file-write":
		if len(os.Args) != 5 {
			err = errors.New("file-write requires an encoded domain, path, and content")
			break
		}
		data, err = writeManagedFileEncoded(os.Args[2], os.Args[3], os.Args[4])
	case "file-delete":
		if len(os.Args) != 4 {
			err = errors.New("file-delete requires an encoded domain and path")
			break
		}
		data, err = deleteManagedFileEncoded(os.Args[2], os.Args[3])
	case "container-list":
		data, err = inspectContainers()
	case "container-install":
		data, err = installContainerRuntime()
	case "container-control":
		if len(os.Args) != 4 {
			err = errors.New("container-control requires an encoded container name and action")
			break
		}
		data, err = controlContainerEncoded(os.Args[2], os.Args[3])
	case "container-logs":
		if len(os.Args) != 4 {
			err = errors.New("container-logs requires an encoded container name and line count")
			break
		}
		data, err = containerLogsEncoded(os.Args[2], os.Args[3])
	case "php-version-list":
		data, err = listPHPVersions()
	case "php-version-install":
		if len(os.Args) != 3 {
			err = errors.New("php-version-install requires a version")
			break
		}
		data, err = installPHPVersion(os.Args[2])
	case "php-version-remove":
		if len(os.Args) != 3 {
			err = errors.New("php-version-remove requires a version")
			break
		}
		data, err = removePHPVersion(os.Args[2])
	case "php-extension-set":
		if len(os.Args) != 5 {
			err = errors.New("php-extension-set requires a version, extension, and install or remove")
			break
		}
		data, err = setPHPExtension(os.Args[2], os.Args[3], os.Args[4])
	case "site-switch-php":
		if len(os.Args) != 4 {
			err = errors.New("site-switch-php requires an encoded domain and PHP version")
			break
		}
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = switchPHP(string(decoded), os.Args[3])
	case "node-install":
		data, err = installNode()
	case "project-create":
		if len(os.Args) != 3 {
			err = errors.New("project-create requires an encoded domain")
			break
		}
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = createNodeProject(string(decoded))
	case "database-list":
		data, err = listDatabases()
	case "database-create":
		if len(os.Args) != 4 {
			err = errors.New("database-create requires encoded database and user names")
			break
		}
		databaseName, databaseErr := base64.RawURLEncoding.DecodeString(os.Args[2])
		username, usernameErr := base64.RawURLEncoding.DecodeString(os.Args[3])
		if databaseErr != nil {
			err = databaseErr
			break
		}
		if usernameErr != nil {
			err = usernameErr
			break
		}
		data, err = createDatabase(string(databaseName), string(username))
	case "tls-list":
		data, err = listTLS()
	case "tls-issue":
		if len(os.Args) != 4 {
			err = errors.New("tls-issue requires encoded domain and email")
			break
		}
		domain, domainErr := base64.RawURLEncoding.DecodeString(os.Args[2])
		email, emailErr := base64.RawURLEncoding.DecodeString(os.Args[3])
		if domainErr != nil {
			err = domainErr
			break
		}
		if emailErr != nil {
			err = emailErr
			break
		}
		data, err = issueTLS(string(domain), string(email))
	case "backup-list":
		data, err = listBackups()
	case "backup-create":
		data, err = createBackup()
	case "backup-export":
		if len(os.Args) != 3 {
			err = errors.New("backup-export requires a backup ID")
			break
		}
		if exportErr := exportBackup(os.Args[2], os.Stdout); exportErr != nil {
			fmt.Fprintln(os.Stderr, exportErr)
			os.Exit(1)
		}
		return
	case "backup-preview":
		if len(os.Args) != 3 {
			err = errors.New("backup-preview requires a backup ID")
			break
		}
		data, err = previewRestore(os.Args[2])
	case "backup-restore":
		if len(os.Args) != 3 {
			err = errors.New("backup-restore requires a backup ID")
			break
		}
		data, err = restoreBackup(os.Args[2])
	case "backup-policy-get":
		data, err = getBackupPolicy()
	case "backup-policy-set":
		if len(os.Args) != 4 {
			err = errors.New("backup-policy-set requires hour and retention")
			break
		}
		hour, hourErr := strconv.Atoi(os.Args[2])
		retention, retentionErr := strconv.Atoi(os.Args[3])
		if hourErr != nil {
			err = hourErr
			break
		}
		if retentionErr != nil {
			err = retentionErr
			break
		}
		data, err = setBackupPolicy(hour, retention)
	case "backup-run":
		data, err = runScheduledBackup()
	case "backup-prune":
		policy, policyErr := getBackupPolicy()
		if policyErr != nil {
			err = policyErr
			break
		}
		data, err = pruneBackups(policy.Retention)
	case "monitoring":
		data, err = inspectMonitoring()
	case "service-logs":
		if len(os.Args) != 4 {
			err = errors.New("service-logs requires encoded service and line count")
			break
		}
		serviceName, decodeErr := base64.RawURLEncoding.DecodeString(os.Args[2])
		lines, linesErr := strconv.Atoi(os.Args[3])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		if linesErr != nil {
			err = linesErr
			break
		}
		data, err = readServiceLogs(string(serviceName), lines)
	case "service-control":
		if len(os.Args) != 4 {
			err = errors.New("service-control requires encoded service and action")
			break
		}
		serviceName, decodeErr := base64.RawURLEncoding.DecodeString(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = controlService(string(serviceName), os.Args[3])
	case "security-status":
		data, err = inspectSecurity()
	case "security-install-fail2ban":
		data, err = installFail2ban()
	case "firewall-enable":
		if len(os.Args) != 3 {
			err = errors.New("firewall-enable requires the SSH port")
			break
		}
		port, portErr := strconv.Atoi(os.Args[2])
		if portErr != nil {
			err = portErr
			break
		}
		data, err = enableFirewall(port)
	case "firewall-confirm":
		data, err = confirmFirewall()
	case "firewall-disable":
		data, err = disableFirewall()
	case "system-update-list":
		data, err = listSystemUpdates()
	case "system-update-apply":
		data, err = applySystemUpdates()
	default:
		err = errors.New("unsupported command")
	}

	result := response{OK: err == nil, Protocol: protocolVersion, Version: version, Data: data}
	if err != nil {
		result.Error = err.Error()
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(result)
	if err != nil {
		os.Exit(1)
	}
}

func detectPublicAddress() (map[string]string, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	request, err := http.NewRequest(http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "ServerDeck-Agent/"+version)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("detect public address: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("detect public address: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if err != nil {
		return nil, fmt.Errorf("read public address response: %w", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "ip=") {
			address := strings.TrimSpace(strings.TrimPrefix(line, "ip="))
			if net.ParseIP(address) == nil {
				return nil, errors.New("public address service returned an invalid IP")
			}
			return map[string]string{"address": address, "source": "Cloudflare"}, nil
		}
	}
	return nil, errors.New("public address was not present in the detection response")
}

func listSystemUpdates() ([]updatePackage, error) {
	output, err := exec.Command("apt", "list", "--upgradable").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list updates: %s", tail(string(output), 800))
	}
	values := []updatePackage{}
	pattern := regexp.MustCompile(`^([^/]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: ([^]]+)\]`)
	for _, line := range strings.Split(string(output), "\n") {
		match := pattern.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) == 4 {
			values = append(values, updatePackage{Name: match[1], Candidate: match[2], Current: match[3]})
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
	return values, nil
}

func applySystemUpdates() (updateResult, error) {
	result := updateResult{}
	if os.Geteuid() != 0 {
		return result, errors.New("system-update-apply must run as root")
	}
	updates, err := listSystemUpdates()
	if err != nil {
		return result, err
	}
	if len(updates) == 0 {
		return updateResult{Summary: "System is already up to date"}, nil
	}
	safety, err := createBackup()
	if err != nil {
		return result, fmt.Errorf("create update safety backup: %w", err)
	}
	_ = writeAudit("system.update.started", true, fmt.Sprintf("%d packages; safety %s", len(updates), safety.ID))
	command := exec.Command("apt-get", "update")
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if output, err := command.CombinedOutput(); err != nil {
		_ = writeAudit("system.update.failed", false, tail(string(output), 800))
		return result, fmt.Errorf("refresh packages: %s", tail(string(output), 800))
	}
	command = exec.Command("apt-get", "upgrade", "-y")
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a")
	output, err := command.CombinedOutput()
	if err != nil {
		_ = writeAudit("system.update.failed", false, tail(string(output), 800))
		return result, fmt.Errorf("apply updates: %s", tail(string(output), 800))
	}
	_, rebootErr := os.Stat("/var/run/reboot-required")
	result = updateResult{Updated: len(updates), SafetyBackupID: safety.ID, RebootRequired: rebootErr == nil, Summary: tail(string(output), 1200)}
	_ = writeAudit("system.update.completed", true, fmt.Sprintf("%d packages; reboot %t", len(updates), result.RebootRequired))
	return result, nil
}

func firewallIsActive() bool {
	output, _ := exec.Command("ufw", "status").CombinedOutput()
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Status:") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "Status:")) == "active"
		}
	}
	return false
}

func enableFirewall(sshPort int) (securityStatus, error) {
	if os.Geteuid() != 0 {
		return securityStatus{}, errors.New("firewall-enable must run as root")
	}
	if sshPort < 1 || sshPort > 65535 {
		return securityStatus{}, errors.New("invalid SSH port")
	}
	_ = exec.Command("systemctl", "stop", "serverdeck-firewall-rollback.timer").Run()
	_ = exec.Command("systemctl", "reset-failed", "serverdeck-firewall-rollback.service").Run()
	if output, err := exec.Command("systemd-run", "--unit=serverdeck-firewall-rollback", "--on-active=2m", "/usr/sbin/ufw", "--force", "disable").CombinedOutput(); err != nil {
		return securityStatus{}, fmt.Errorf("schedule firewall rollback: %s", tail(string(output), 800))
	}
	rules := [][]string{{"allow", fmt.Sprintf("%d/tcp", sshPort), "comment", "ServerDeck SSH"}, {"allow", "80/tcp", "comment", "ServerDeck HTTP"}, {"allow", "443/tcp", "comment", "ServerDeck HTTPS"}}
	for _, arguments := range rules {
		if output, err := exec.Command("ufw", arguments...).CombinedOutput(); err != nil {
			return securityStatus{}, fmt.Errorf("add firewall rule: %s", tail(string(output), 800))
		}
	}
	if output, err := exec.Command("ufw", "--force", "enable").CombinedOutput(); err != nil {
		return securityStatus{}, fmt.Errorf("enable firewall: %s", tail(string(output), 800))
	}
	_ = writeAudit("firewall.enable.pending", true, fmt.Sprintf("SSH %d; rollback in 2 minutes", sshPort))
	return inspectSecurity()
}

func confirmFirewall() (securityStatus, error) {
	if os.Geteuid() != 0 {
		return securityStatus{}, errors.New("firewall-confirm must run as root")
	}
	_ = exec.Command("systemctl", "stop", "serverdeck-firewall-rollback.timer").Run()
	_ = exec.Command("systemctl", "stop", "serverdeck-firewall-rollback.service").Run()
	_ = writeAudit("firewall.enable.confirmed", true, "fresh SSH connection verified")
	return inspectSecurity()
}

func disableFirewall() (securityStatus, error) {
	if os.Geteuid() != 0 {
		return securityStatus{}, errors.New("firewall-disable must run as root")
	}
	_ = exec.Command("systemctl", "stop", "serverdeck-firewall-rollback.timer").Run()
	if output, err := exec.Command("ufw", "--force", "disable").CombinedOutput(); err != nil {
		return securityStatus{}, fmt.Errorf("disable firewall: %s", tail(string(output), 800))
	}
	_ = writeAudit("firewall.disabled", true, "UFW disabled")
	return inspectSecurity()
}

func inspectSecurity() (securityStatus, error) {
	value := securityStatus{FirewallRules: []string{}, Findings: []string{}}
	ufwOutput, _ := exec.Command("ufw", "status").CombinedOutput()
	for _, line := range strings.Split(string(ufwOutput), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Status:") {
			value.FirewallActive = strings.TrimSpace(strings.TrimPrefix(trimmed, "Status:")) == "active"
		}
		if strings.Contains(trimmed, "ALLOW") || strings.Contains(trimmed, "DENY") || strings.Contains(trimmed, "LIMIT") {
			value.FirewallRules = append(value.FirewallRules, trimmed)
		}
	}
	value.Fail2banInstalled = strings.TrimSpace(systemctl("show", "fail2ban.service", "--property=LoadState", "--value")) == "loaded"
	value.Fail2banActive = strings.TrimSpace(systemctl("is-active", "fail2ban.service")) == "active"
	sshdOutput, _ := exec.Command("sshd", "-T").CombinedOutput()
	for _, line := range strings.Split(string(sshdOutput), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "permitrootlogin":
			value.PermitRootLogin = fields[1]
		case "passwordauthentication":
			value.PasswordAuthentication = fields[1]
		case "pubkeyauthentication":
			value.PubkeyAuthentication = fields[1]
		}
	}
	updates, _ := exec.Command("apt", "list", "--upgradable").CombinedOutput()
	for _, line := range strings.Split(string(updates), "\n") {
		if strings.Contains(line, "/") && !strings.HasPrefix(line, "Listing") {
			value.UpdatesAvailable++
		}
	}
	if !value.FirewallActive {
		value.Findings = append(value.Findings, "Firewall is not active")
	}
	if !value.Fail2banActive {
		value.Findings = append(value.Findings, "Fail2ban is not protecting SSH")
	}
	if value.PermitRootLogin == "yes" {
		value.Findings = append(value.Findings, "SSH root login is allowed")
	}
	if value.PasswordAuthentication == "yes" {
		value.Findings = append(value.Findings, "SSH password authentication is allowed")
	}
	if value.PubkeyAuthentication != "yes" {
		value.Findings = append(value.Findings, "SSH public-key authentication is not enabled")
	}
	if value.UpdatesAvailable > 0 {
		value.Findings = append(value.Findings, fmt.Sprintf("%d system updates are available", value.UpdatesAvailable))
	}
	return value, nil
}

func installFail2ban() (securityStatus, error) {
	if os.Geteuid() != 0 {
		return securityStatus{}, errors.New("security-install-fail2ban must run as root")
	}
	if output, err := exec.Command("apt-get", "install", "-y", "--no-install-recommends", "fail2ban").CombinedOutput(); err != nil {
		return securityStatus{}, fmt.Errorf("install Fail2ban: %s", tail(string(output), 800))
	}
	configuration := "[sshd]\nenabled = true\nbackend = systemd\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n"
	if err := atomicWrite("/etc/fail2ban/jail.d/serverdeck.local", []byte(configuration), 0644); err != nil {
		return securityStatus{}, err
	}
	if output, err := exec.Command("systemctl", "enable", "--now", "fail2ban").CombinedOutput(); err != nil {
		return securityStatus{}, fmt.Errorf("enable Fail2ban: %s", tail(string(output), 800))
	}
	if err := exec.Command("systemctl", "restart", "fail2ban").Run(); err != nil {
		return securityStatus{}, err
	}
	_ = writeAudit("security.fail2ban.installed", true, "sshd jail enabled")
	return inspectSecurity()
}

func allowedService(name string) bool {
	if _, ok := managedServices[name]; ok {
		return true
	}
	if regexp.MustCompile(`^php[0-9]+\.[0-9]+-fpm$`).MatchString(name) {
		return strings.TrimSpace(systemctl("show", name+".service", "--property=LoadState", "--value")) == "loaded"
	}
	if regexp.MustCompile(`^serverdeck-[a-f0-9]{12}$`).MatchString(name) {
		sites, _ := listSites()
		for _, site := range sites {
			if site.Service == name {
				return true
			}
		}
	}
	return false
}

func readServiceLogs(name string, lines int) (serviceLogs, error) {
	if !allowedService(name) {
		return serviceLogs{}, errors.New("service is not managed by ServerDeck")
	}
	if lines < 1 || lines > 1000 {
		return serviceLogs{}, errors.New("log line count must be between 1 and 1000")
	}
	output, err := exec.Command("journalctl", "--unit", name+".service", "--no-pager", "--lines", strconv.Itoa(lines), "--output", "short-iso").CombinedOutput()
	if err != nil {
		return serviceLogs{}, fmt.Errorf("read service logs: %s", tail(string(output), 1000))
	}
	return serviceLogs{Service: name, Lines: string(output)}, nil
}

func controlService(name, action string) (service, error) {
	if os.Geteuid() != 0 {
		return service{}, errors.New("service-control must run as root")
	}
	if !allowedService(name) {
		return service{}, errors.New("service is not managed by ServerDeck")
	}
	if action != "start" && action != "stop" && action != "restart" {
		return service{}, errors.New("action must be start, stop, or restart")
	}
	output, err := exec.Command("systemctl", action, name+".service").CombinedOutput()
	if err != nil {
		_ = writeAudit("service."+action+".failed", false, name+": "+tail(string(output), 800))
		return service{}, fmt.Errorf("service %s failed: %s", action, tail(string(output), 800))
	}
	active := strings.TrimSpace(systemctl("is-active", name+".service")) == "active"
	_ = writeAudit("service."+action+".completed", true, name)
	description := managedServices[name]
	if description == "" {
		description = "Managed application service"
	}
	return service{Name: name, Installed: true, Active: active, Description: description}, nil
}

func inspectMonitoring() (monitoringStatus, error) {
	value := monitoringStatus{FailedUnits: []string{}, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	contents, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return value, err
	}
	fields := strings.Fields(string(contents))
	if len(fields) >= 3 {
		value.Load1, _ = strconv.ParseFloat(fields[0], 64)
		value.Load5, _ = strconv.ParseFloat(fields[1], 64)
		value.Load15, _ = strconv.ParseFloat(fields[2], 64)
	}
	failed, _ := exec.Command("systemctl", "--failed", "--no-legend", "--plain", "--no-pager").Output()
	for _, line := range strings.Split(string(failed), "\n") {
		parts := strings.Fields(line)
		if len(parts) > 0 {
			value.FailedUnits = append(value.FailedUnits, parts[0])
		}
	}
	services, _ := inspectServices()
	for _, service := range services {
		if service.Active {
			value.Running++
		}
	}
	return value, nil
}

func getBackupPolicy() (backupPolicy, error) {
	value := backupPolicy{Enabled: false, Hour: 3, Retention: 7, Timer: "serverdeck-backup.timer"}
	contents, err := os.ReadFile("/var/lib/serverdeck/backup-policy.json")
	if os.IsNotExist(err) {
		return value, nil
	}
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(contents, &value); err != nil {
		return value, err
	}
	return value, nil
}

func setBackupPolicy(hour, retention int) (backupPolicy, error) {
	value := backupPolicy{}
	if os.Geteuid() != 0 {
		return value, errors.New("backup-policy-set must run as root")
	}
	if hour < 0 || hour > 23 {
		return value, errors.New("backup hour must be between 0 and 23")
	}
	if retention < 1 || retention > 100 {
		return value, errors.New("retention must be between 1 and 100 backups")
	}
	service := "[Unit]\nDescription=Create a verified ServerDeck backup\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/serverdeck-agent backup-run\nNice=10\nIOSchedulingClass=best-effort\nIOSchedulingPriority=7\n"
	timer := fmt.Sprintf("[Unit]\nDescription=Daily ServerDeck backup\n\n[Timer]\nOnCalendar=*-*-* %02d:00:00\nPersistent=true\nRandomizedDelaySec=10m\nUnit=serverdeck-backup.service\n\n[Install]\nWantedBy=timers.target\n", hour)
	if err := atomicWrite("/etc/systemd/system/serverdeck-backup.service", []byte(service), 0644); err != nil {
		return value, err
	}
	if err := atomicWrite("/etc/systemd/system/serverdeck-backup.timer", []byte(timer), 0644); err != nil {
		return value, err
	}
	value = backupPolicy{Enabled: true, Hour: hour, Retention: retention, Timer: "serverdeck-backup.timer"}
	encoded, _ := json.MarshalIndent(value, "", "  ")
	if err := atomicWrite("/var/lib/serverdeck/backup-policy.json", append(encoded, '\n'), 0644); err != nil {
		return backupPolicy{}, err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if output, err := exec.Command("systemctl", "enable", "--now", "serverdeck-backup.timer").CombinedOutput(); err != nil {
		return backupPolicy{}, fmt.Errorf("enable backup timer: %s", tail(string(output), 800))
	}
	_ = writeAudit("backup.policy.updated", true, fmt.Sprintf("daily %02d:00 retain %d", hour, retention))
	return value, nil
}

func runScheduledBackup() (map[string]interface{}, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("backup-run must run as root")
	}
	created, err := createBackup()
	if err != nil {
		return nil, err
	}
	policy, err := getBackupPolicy()
	if err != nil {
		return nil, err
	}
	removed, err := pruneBackups(policy.Retention)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"backup": created, "removed": removed}, nil
}

func pruneBackups(retention int) ([]string, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("backup-prune must run as root")
	}
	values, err := listBackups()
	if err != nil {
		return nil, err
	}
	removed := []string{}
	for index, value := range values {
		if index < retention {
			continue
		}
		if !regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`).MatchString(value.ID) {
			continue
		}
		if err := os.RemoveAll(filepath.Join("/var/backups/serverdeck", value.ID)); err != nil {
			return removed, err
		}
		removed = append(removed, value.ID)
		_ = writeAudit("backup.pruned", true, value.ID)
	}
	return removed, nil
}

func loadVerifiedBackup(id string) (backup, error) {
	value := backup{}
	if !regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`).MatchString(id) {
		return value, errors.New("invalid backup ID")
	}
	manifestPath := filepath.Join("/var/backups/serverdeck", id, "manifest.json")
	contents, err := os.ReadFile(manifestPath)
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(contents, &value); err != nil {
		return value, err
	}
	checksum, err := fileSHA256(value.Archive)
	if err != nil || checksum != value.SHA256 {
		return value, errors.New("backup integrity verification failed")
	}
	return value, nil
}

func previewRestore(id string) (restorePreview, error) {
	value, err := loadVerifiedBackup(id)
	if err != nil {
		return restorePreview{}, err
	}
	currentSites, _ := listSites()
	currentDatabases, _ := listDatabases()
	siteSet, databaseSet := map[string]bool{}, map[string]bool{}
	for _, item := range currentSites {
		siteSet[item.Domain] = true
	}
	for _, item := range currentDatabases {
		databaseSet[item.Name] = true
	}
	preview := restorePreview{Backup: value, ConflictingSites: []string{}, ConflictingDBs: []string{}}
	for _, item := range value.Sites {
		if siteSet[item] {
			preview.ConflictingSites = append(preview.ConflictingSites, item)
		}
	}
	for _, item := range value.Databases {
		if databaseSet[item] {
			preview.ConflictingDBs = append(preview.ConflictingDBs, item)
		}
	}
	return preview, nil
}

func restoreBackup(id string) (restoreResult, error) {
	result := restoreResult{}
	if os.Geteuid() != 0 {
		return result, errors.New("backup-restore must run as root")
	}
	value, err := loadVerifiedBackup(id)
	if err != nil {
		return result, err
	}
	_ = writeAudit("backup.restore.started", true, id)
	safety, err := createBackup()
	if err != nil {
		return result, fmt.Errorf("create safety backup: %w", err)
	}
	staging, err := os.MkdirTemp("/var/lib/serverdeck", ".restore-*")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(staging)
	if output, err := exec.Command("tar", "-xzf", value.Archive, "-C", staging).CombinedOutput(); err != nil {
		return result, fmt.Errorf("extract backup: %s", tail(string(output), 800))
	}

	configSafety, err := os.MkdirTemp("/var/lib/serverdeck", ".web-config-safety-*")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(configSafety)
	for _, serverName := range []string{"nginx", "apache2"} {
		serverSafety := filepath.Join(configSafety, serverName)
		_ = os.MkdirAll(serverSafety, 0755)
		for _, directory := range []string{"sites-available", "sites-enabled"} {
			_ = exec.Command("cp", "-a", filepath.Join("/etc", serverName, directory), serverSafety).Run()
		}
	}
	rollbackWebConfig := func() {
		for _, serverName := range []string{"nginx", "apache2"} {
			for _, directory := range []string{"sites-available", "sites-enabled"} {
				saved := filepath.Join(configSafety, serverName, directory)
				if _, err := os.Stat(saved); err == nil {
					_ = os.RemoveAll(filepath.Join("/etc", serverName, directory))
					_ = exec.Command("cp", "-a", saved, filepath.Join("/etc", serverName)+"/").Run()
				}
			}
		}
		if packageVersion("nginx") != "" { _ = exec.Command("systemctl", "reload", "nginx").Run() }
		if packageVersion("apache2") != "" { _ = exec.Command("systemctl", "reload", "apache2").Run() }
	}
	for _, serverName := range []string{"nginx", "apache2"} {
		for _, directory := range []string{"sites-available", "sites-enabled"} {
			source := filepath.Join(staging, "etc", serverName, directory)
			if _, err := os.Stat(source); err == nil {
				if output, err := exec.Command("cp", "-a", source+"/.", filepath.Join("/etc", serverName, directory)).CombinedOutput(); err != nil {
					rollbackWebConfig()
					return result, fmt.Errorf("restore %s configuration: %s", serverName, tail(string(output), 800))
				}
			}
		}
	}
	for _, domain := range value.Sites {
		pairs := [][2]string{{filepath.Join(staging, "var/www", domain), filepath.Join("/var/www", domain)}, {filepath.Join(staging, "var/lib/serverdeck/sites", domain+".json"), filepath.Join("/var/lib/serverdeck/sites", domain+".json")}}
		for _, pair := range pairs {
			if _, err := os.Stat(pair[0]); err == nil {
				_ = os.RemoveAll(pair[1])
				if output, err := exec.Command("cp", "-a", pair[0], pair[1]).CombinedOutput(); err != nil {
					rollbackWebConfig()
					return result, fmt.Errorf("restore site %s: %s", domain, tail(string(output), 800))
				}
			}
		}
	}
	if packageVersion("nginx") != "" {
		if output, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
			rollbackWebConfig()
			return result, fmt.Errorf("restored Nginx validation failed: %s", tail(string(output), 800))
		}
		if err := exec.Command("systemctl", "reload", "nginx").Run(); err != nil {
			rollbackWebConfig()
			return result, err
		}
	}
	if packageVersion("apache2") != "" {
		if output, err := exec.Command("apache2ctl", "configtest").CombinedOutput(); err != nil {
			rollbackWebConfig()
			return result, fmt.Errorf("restored Apache validation failed: %s", tail(string(output), 800))
		}
		if err := exec.Command("systemctl", "reload", "apache2").Run(); err != nil {
			rollbackWebConfig()
			return result, err
		}
	}
	for _, name := range value.Databases {
		dump := filepath.Join(staging, "var/backups/serverdeck", id, "databases", name+".sql")
		file, openErr := os.Open(dump)
		if openErr != nil {
			return result, openErr
		}
		engine := ""
		metadataPath := filepath.Join(staging, "var/lib/serverdeck/databases", name+".json")
		if _, statErr := os.Stat(metadataPath); statErr != nil {
			metadataPath = filepath.Join("/var/lib/serverdeck/databases", name+".json")
		}
		if metadata, readErr := os.ReadFile(metadataPath); readErr == nil {
			var managed database
			if json.Unmarshal(metadata, &managed) == nil {
				engine = managed.Engine
			}
		}
		command := exec.Command("mariadb", name)
		if engine == "MySQL" {
			command = exec.Command("mysql", name)
		} else if engine == "PostgreSQL" {
			command = exec.Command("runuser", "-u", "postgres", "--", "psql", "--set", "ON_ERROR_STOP=1", "--dbname", name)
		}
		command.Stdin = file
		output, importErr := command.CombinedOutput()
		file.Close()
		if importErr != nil {
			_ = writeAudit("backup.restore.failed", false, name+": "+tail(string(output), 800))
			return result, fmt.Errorf("restore database %s: %s", name, tail(string(output), 800))
		}
	}
	_ = writeAudit("backup.restore.completed", true, id+" safety "+safety.ID)
	return restoreResult{RestoredBackupID: id, SafetyBackupID: safety.ID, Sites: len(value.Sites), Databases: len(value.Databases)}, nil
}

func exportBackup(id string, destination io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("backup-export must run as root")
	}
	value, err := loadVerifiedBackup(id)
	if err != nil {
		return err
	}
	file, err := os.Open(value.Archive)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(destination, file)
	return err
}

func listBackups() ([]backup, error) {
	paths, err := filepath.Glob("/var/backups/serverdeck/*/manifest.json")
	if err != nil {
		return nil, err
	}
	values := make([]backup, 0, len(paths))
	for _, path := range paths {
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		var value backup
		if err := json.Unmarshal(contents, &value); err != nil {
			return nil, err
		}
		checksum, checksumErr := fileSHA256(value.Archive)
		value.Verified = checksumErr == nil && checksum == value.SHA256
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].CreatedAt > values[j].CreatedAt })
	return values, nil
}

func createBackup() (backup, error) {
	value := backup{}
	if os.Geteuid() != 0 {
		return value, errors.New("backup-create must run as root")
	}
	id := time.Now().UTC().Format("20060102T150405Z")
	root := filepath.Join("/var/backups/serverdeck", id)
	if err := os.MkdirAll(filepath.Join(root, "databases"), 0700); err != nil {
		return value, err
	}
	_ = writeAudit("backup.create.started", true, id)

	databases, err := listDatabases()
	if err != nil {
		return value, err
	}
	databaseNames := make([]string, 0, len(databases))
	for _, database := range databases {
		destination := filepath.Join(root, "databases", database.Name+".sql")
		command := exec.Command("mariadb-dump", "--single-transaction", "--routines", "--triggers", "--result-file="+destination, database.Name)
		if database.Engine == "MySQL" {
			command = exec.Command("mysqldump", "--single-transaction", "--routines", "--triggers", "--result-file="+destination, database.Name)
		} else if database.Engine == "PostgreSQL" {
			command = exec.Command("runuser", "-u", "postgres", "--", "pg_dump", "--clean", "--if-exists", "--file", destination, database.Name)
		}
		if output, err := command.CombinedOutput(); err != nil {
			_ = writeAudit("backup.create.failed", false, database.Name+": "+tail(string(output), 800))
			return value, fmt.Errorf("database dump failed for %s: %s", database.Name, tail(string(output), 800))
		}
		databaseNames = append(databaseNames, database.Name)
	}
	sites, err := listSites()
	if err != nil {
		return value, err
	}
	siteNames := make([]string, 0, len(sites))
	for _, site := range sites {
		siteNames = append(siteNames, site.Domain)
	}

	archive := filepath.Join(root, "serverdeck-backup.tar.gz")
	paths := []string{"-czf", archive}
	for _, path := range []string{"/var/lib/serverdeck", "/etc/nginx/sites-available", "/etc/nginx/sites-enabled", "/etc/apache2/sites-available", "/etc/apache2/sites-enabled", "/var/www", filepath.Join(root, "databases")} {
		if _, err := os.Stat(path); err == nil {
			paths = append(paths, path)
		}
	}
	units, _ := filepath.Glob("/etc/systemd/system/serverdeck-*.service")
	paths = append(paths, units...)
	if output, err := exec.Command("tar", paths...).CombinedOutput(); err != nil {
		_ = writeAudit("backup.create.failed", false, tail(string(output), 800))
		return value, fmt.Errorf("archive creation failed: %s", tail(string(output), 800))
	}
	checksum, err := fileSHA256(archive)
	if err != nil {
		return value, err
	}
	info, err := os.Stat(archive)
	if err != nil {
		return value, err
	}
	value = backup{ID: id, CreatedAt: time.Now().UTC().Format(time.RFC3339), Archive: archive, Size: info.Size(), SHA256: checksum, Sites: siteNames, Databases: databaseNames, Verified: true}
	manifest, _ := json.MarshalIndent(value, "", "  ")
	if err := atomicWrite(filepath.Join(root, "manifest.json"), append(manifest, '\n'), 0644); err != nil {
		return backup{}, err
	}
	_ = writeAudit("backup.create.completed", true, fmt.Sprintf("%s %d bytes", id, info.Size()))
	return value, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func listTLS() ([]tlsStatus, error) {
	sites, err := listSites()
	if err != nil {
		return nil, err
	}
	statuses := make([]tlsStatus, 0, len(sites))
	for _, value := range sites {
		statuses = append(statuses, inspectTLS(value.Domain))
	}
	return statuses, nil
}

func inspectTLS(domain string) tlsStatus {
	status := tlsStatus{Domain: domain, DNSAddresses: []string{}, ServerIPs: localIPs()}
	addresses, _ := net.LookupHost(domain)
	seen := map[string]bool{}
	for _, address := range addresses {
		parsed := net.ParseIP(address)
		if parsed == nil || parsed.To4() == nil || seen[address] {
			continue
		}
		seen[address] = true
		status.DNSAddresses = append(status.DNSAddresses, address)
	}
	sort.Strings(status.DNSAddresses)
	for _, dns := range status.DNSAddresses {
		for _, local := range status.ServerIPs {
			if dns == local {
				status.Ready = true
			}
		}
	}
	certificatePath := filepath.Join("/etc/letsencrypt/live", domain, "cert.pem")
	if _, err := os.Stat(certificatePath); err == nil {
		status.Certificate = true
		if output, err := exec.Command("openssl", "x509", "-in", certificatePath, "-noout", "-enddate").Output(); err == nil {
			status.ExpiresAt = strings.TrimSpace(strings.TrimPrefix(string(output), "notAfter="))
		}
	}
	if status.Certificate {
		status.Message = "Certificate installed"
	} else if len(status.DNSAddresses) == 0 {
		status.Message = "Domain does not resolve in public DNS"
	} else if !status.Ready {
		status.Message = "DNS does not point to an address on this server"
	} else {
		status.Message = "Ready for Let’s Encrypt"
	}
	return status
}

func localIPs() []string {
	addresses, _ := net.InterfaceAddrs()
	values := []string{}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() {
			values = append(values, ip.String())
		}
	}
	sort.Strings(values)
	return values
}

func issueTLS(domain, email string) (tlsStatus, error) {
	if os.Geteuid() != 0 {
		return tlsStatus{}, errors.New("tls-issue must run as root")
	}
	domain, email = strings.ToLower(strings.TrimSpace(domain)), strings.TrimSpace(email)
	if !domainPattern.MatchString(domain) || !regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`).MatchString(email) {
		return tlsStatus{}, errors.New("invalid domain or email address")
	}
	metadataPath := filepath.Join("/var/lib/serverdeck/sites", domain+".json")
	metadata, err := os.ReadFile(metadataPath)
	if err != nil {
		return tlsStatus{}, errors.New("managed website was not found")
	}
	var managedSite site
	if err := json.Unmarshal(metadata, &managedSite); err != nil {
		return tlsStatus{}, err
	}
	readiness := inspectTLS(domain)
	if !readiness.Ready {
		return readiness, errors.New(readiness.Message)
	}
	webServer := managedSite.WebServer
	if webServer == "" {
		webServer = "nginx"
	}
	configPath := filepath.Join("/etc/nginx/sites-available", domain)
	if webServer == "apache" {
		configPath = filepath.Join("/etc/apache2/sites-available", domain+".conf")
	}
	original, err := os.ReadFile(configPath)
	if err != nil {
		return readiness, err
	}
	_ = writeAudit("tls.issue.started", true, domain)
	arguments := []string{"certonly", "--nginx", "--non-interactive", "--agree-tos", "--keep-until-expiring", "--email", email, "--domain", domain}
	if webServer == "apache" {
		arguments = []string{"--apache", "--non-interactive", "--agree-tos", "--keep-until-expiring", "--redirect", "--email", email, "--domain", domain}
	}
	if output, err := exec.Command("certbot", arguments...).CombinedOutput(); err != nil {
		_ = atomicWrite(configPath, original, 0644)
		_ = exec.Command("systemctl", "reload", map[string]string{"nginx": "nginx", "apache": "apache2"}[webServer]).Run()
		_ = writeAudit("tls.issue.failed", false, domain+": "+tail(string(output), 800))
		return readiness, fmt.Errorf("Certbot failed: %s", tail(string(output), 800))
	}
	if webServer == "apache" {
		if output, err := exec.Command("apache2ctl", "configtest").CombinedOutput(); err != nil {
			_ = writeAudit("tls.issue.failed", false, domain+": "+tail(string(output), 800))
			return readiness, fmt.Errorf("Apache TLS validation failed: %s", tail(string(output), 800))
		}
		if err := exec.Command("systemctl", "reload", "apache2").Run(); err != nil {
			return readiness, err
		}
		_ = writeAudit("tls.issue.completed", true, domain)
		return inspectTLS(domain), nil
	}
	certificatePath := filepath.Join("/etc/letsencrypt/live", domain)
	tlsBlock := fmt.Sprintf("\n    listen 443 ssl;\n    listen [::]:443 ssl;\n    ssl_certificate %s/fullchain.pem;\n    ssl_certificate_key %s/privkey.pem;\n", certificatePath, certificatePath)
	updated := strings.Replace(string(original), "server {", "server {"+tlsBlock, 1)
	if err := atomicWrite(configPath, []byte(updated), 0644); err != nil {
		return readiness, err
	}
	rollback := func() {
		_ = atomicWrite(configPath, original, 0644)
		_ = exec.Command("systemctl", "reload", "nginx").Run()
	}
	if output, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		rollback()
		return readiness, fmt.Errorf("Nginx TLS validation failed: %s", tail(string(output), 800))
	}
	if err := exec.Command("systemctl", "reload", "nginx").Run(); err != nil {
		rollback()
		return readiness, err
	}
	_ = writeAudit("tls.issue.completed", true, domain)
	return inspectTLS(domain), nil
}

func listDatabases() ([]database, error) {
	paths, err := filepath.Glob("/var/lib/serverdeck/databases/*.json")
	if err != nil {
		return nil, err
	}
	values := make([]database, 0, len(paths))
	for _, path := range paths {
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		var value database
		if err := json.Unmarshal(contents, &value); err != nil {
			return nil, err
		}
		value.Password = ""
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Name < values[j].Name })
	return values, nil
}

func createDatabase(name, username string) (database, error) {
	value := database{}
	if os.Geteuid() != 0 {
		return value, errors.New("database-create must run as root")
	}
	name, username = strings.ToLower(strings.TrimSpace(name)), strings.ToLower(strings.TrimSpace(username))
	if !databaseNamePattern.MatchString(name) || !databaseNamePattern.MatchString(username) {
		return value, errors.New("database and user names must start with a letter and contain only lowercase letters, numbers, or underscores")
	}
	metadataPath := filepath.Join("/var/lib/serverdeck/databases", name+".json")
	if _, err := os.Stat(metadataPath); err == nil {
		return value, errors.New("a managed database with this name already exists")
	}
	password, err := randomPassword(28)
	if err != nil {
		return value, err
	}
	databaseClient := ""
	engine := ""
	if packageVersion("mariadb-server") != "" {
		databaseClient = "mariadb"
		engine = "MariaDB"
	} else if packageVersion("mysql-server") != "" {
		databaseClient = "mysql"
		engine = "MySQL"
	} else if packageVersion("postgresql") != "" {
		engine = "PostgreSQL"
	} else {
		return value, errors.New("MariaDB, MySQL, or PostgreSQL must be installed before creating a managed database")
	}
	if engine == "PostgreSQL" {
		roleSQL := fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", username, password)
		if output, err := exec.Command("runuser", "-u", "postgres", "--", "psql", "--set", "ON_ERROR_STOP=1", "--command", roleSQL).CombinedOutput(); err != nil {
			_ = writeAudit("database.create.failed", false, name+": "+tail(string(output), 500))
			return value, fmt.Errorf("PostgreSQL rejected role creation: %s", tail(string(output), 500))
		}
		if output, err := exec.Command("runuser", "-u", "postgres", "--", "createdb", "--owner", username, name).CombinedOutput(); err != nil {
			_ = exec.Command("runuser", "-u", "postgres", "--", "dropuser", "--if-exists", username).Run()
			_ = writeAudit("database.create.failed", false, name+": "+tail(string(output), 500))
			return value, fmt.Errorf("PostgreSQL rejected database creation: %s", tail(string(output), 500))
		}
	} else {
		sql := fmt.Sprintf("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER '%s'@'localhost' IDENTIFIED BY '%s'; GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost'; FLUSH PRIVILEGES;", name, username, password, name, username)
		if output, err := exec.Command(databaseClient, "--batch", "--skip-column-names", "--execute", sql).CombinedOutput(); err != nil {
			_ = writeAudit("database.create.failed", false, name+": "+tail(string(output), 500))
			return value, fmt.Errorf("%s rejected database creation: %s", engine, tail(string(output), 500))
		}
	}
	value = database{Name: name, Username: username, Host: "localhost", CreatedAt: time.Now().UTC().Format(time.RFC3339), Password: password, Engine: engine}
	metadataValue := value
	metadataValue.Password = ""
	encoded, _ := json.MarshalIndent(metadataValue, "", "  ")
	if err := atomicWrite(metadataPath, append(encoded, '\n'), 0644); err != nil {
		if engine == "PostgreSQL" {
			_ = exec.Command("runuser", "-u", "postgres", "--", "dropdb", "--if-exists", name).Run()
			_ = exec.Command("runuser", "-u", "postgres", "--", "dropuser", "--if-exists", username).Run()
		} else {
			cleanup := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`; DROP USER IF EXISTS '%s'@'localhost';", name, username)
			_ = exec.Command(databaseClient, "--execute", cleanup).Run()
		}
		return database{}, err
	}
	_ = writeAudit("database.create.completed", true, name+" user "+username)
	return value, nil
}

func randomPassword(length int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	buffer := make([]byte, length)
	random := make([]byte, length)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	for index := range buffer {
		buffer[index] = alphabet[int(random[index])%len(alphabet)]
	}
	return string(buffer), nil
}

func packageVersion(name string) string {
	output, err := exec.Command("dpkg-query", "-W", "-f=${Status}\t${Version}", name).Output()
	if err != nil {
		return ""
	}
	parts := strings.SplitN(strings.TrimSpace(string(output)), "\t", 2)
	if len(parts) == 2 && strings.HasPrefix(parts[0], "install ok installed") {
		return parts[1]
	}
	return ""
}

func inspectMail() (mailStatus, error) {
	hostname, _ := os.Hostname()
	status := mailStatus{
		Hostname:         hostname,
		PostfixInstalled: packageVersion("postfix") != "",
		PostfixActive:    unitActive("postfix"),
		DovecotInstalled: packageVersion("dovecot-core") != "",
		DovecotActive:    unitActive("dovecot"),
	}
	if value, err := os.ReadFile("/etc/mailname"); err == nil {
		status.Mailname = strings.TrimSpace(string(value))
	}
	status.ReadyForSetup = status.PostfixInstalled && status.PostfixActive && status.DovecotInstalled && status.DovecotActive
	return status, nil
}

func inspectContainers() (containerInventory, error) {
	result := containerInventory{Installed: packageVersion("docker.io") != "", Active: unitActive("docker"), Containers: []containerStatus{}}
	if !result.Installed {
		return result, nil
	}
	if output, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Output(); err == nil {
		result.Version = strings.TrimSpace(string(output))
	}
	if !result.Active {
		return result, nil
	}
	output, err := exec.Command("docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}").CombinedOutput()
	if err != nil {
		return result, fmt.Errorf("list containers: %s", tail(string(output), 800))
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var raw map[string]string
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return result, fmt.Errorf("decode container inventory: %w", err)
		}
		result.Containers = append(result.Containers, containerStatus{ID: raw["ID"], Name: raw["Names"], Image: raw["Image"], State: raw["State"], Status: raw["Status"], Ports: raw["Ports"], Created: raw["CreatedAt"]})
	}
	sort.Slice(result.Containers, func(i, j int) bool { return result.Containers[i].Name < result.Containers[j].Name })
	return result, nil
}

func installContainerRuntime() (containerInventory, error) {
	if os.Geteuid() != 0 {
		return containerInventory{}, errors.New("container-install must run as root")
	}
	command := exec.Command("apt-get", "install", "-y", "--no-install-recommends", "docker.io")
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	output, err := command.CombinedOutput()
	if err != nil {
		return containerInventory{}, fmt.Errorf("install Docker: %s", tail(string(output), 1200))
	}
	if output, err := exec.Command("systemctl", "enable", "--now", "docker").CombinedOutput(); err != nil {
		return containerInventory{}, fmt.Errorf("start Docker: %s", tail(string(output), 800))
	}
	_ = writeAudit("container.runtime.installed", true, "docker.io")
	return inspectContainers()
}

var containerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func controlContainerEncoded(encodedName, action string) (containerInventory, error) {
	if os.Geteuid() != 0 {
		return containerInventory{}, errors.New("container-control must run as root")
	}
	name, err := decodeArgument(encodedName)
	if err != nil || !containerNamePattern.MatchString(name) {
		return containerInventory{}, errors.New("invalid container name")
	}
	if action != "start" && action != "stop" && action != "restart" {
		return containerInventory{}, errors.New("unsupported container action")
	}
	output, err := exec.Command("docker", action, "--", name).CombinedOutput()
	if err != nil {
		return containerInventory{}, fmt.Errorf("%s container: %s", action, tail(string(output), 800))
	}
	_ = writeAudit("container."+action, true, name)
	return inspectContainers()
}

func containerLogsEncoded(encodedName, encodedLines string) (containerLogs, error) {
	name, err := decodeArgument(encodedName)
	if err != nil || !containerNamePattern.MatchString(name) {
		return containerLogs{}, errors.New("invalid container name")
	}
	linesValue, err := decodeArgument(encodedLines)
	if err != nil {
		return containerLogs{}, err
	}
	lines, err := strconv.Atoi(linesValue)
	if err != nil || lines < 20 || lines > 1000 {
		return containerLogs{}, errors.New("log line count must be between 20 and 1000")
	}
	output, err := exec.Command("docker", "logs", "--tail", strconv.Itoa(lines), "--", name).CombinedOutput()
	if err != nil {
		return containerLogs{}, fmt.Errorf("read container logs: %s", tail(string(output), 800))
	}
	return containerLogs{Container: name, Lines: tail(string(output), 256*1024)}, nil
}

func decodeArgument(value string) (string, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", errors.New("invalid encoded argument")
	}
	return string(decoded), nil
}

func managedSitePath(encodedDomain, encodedPath string) (string, string, error) {
	domain, err := decodeArgument(encodedDomain)
	if err != nil {
		return "", "", err
	}
	relative, err := decodeArgument(encodedPath)
	if err != nil {
		return "", "", err
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) {
		return "", "", errors.New("invalid managed domain")
	}
	metadata, err := os.ReadFile(filepath.Join("/var/lib/serverdeck/sites", domain+".json"))
	if err != nil {
		return "", "", errors.New("managed website was not found")
	}
	var siteValue site
	if err := json.Unmarshal(metadata, &siteValue); err != nil {
		return "", "", err
	}
	root := filepath.Clean(siteValue.Root)
	expected := filepath.Clean(filepath.Join("/var/www", domain, "public"))
	if root != expected {
		return "", "", errors.New("website root is outside the managed file boundary")
	}
	relative = filepath.Clean(strings.TrimSpace(relative))
	if relative == "." {
		relative = ""
	}
	if filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", "", errors.New("path traversal is not allowed")
	}
	target := filepath.Clean(filepath.Join(root, relative))
	if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
		return "", "", errors.New("path is outside the website root")
	}
	parent := target
	if info, statErr := os.Lstat(target); statErr == nil && !info.IsDir() {
		parent = filepath.Dir(target)
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		resolvedParent, err = filepath.EvalSymlinks(filepath.Dir(parent))
	}
	if err == nil && resolvedParent != root && !strings.HasPrefix(resolvedParent, root+string(os.PathSeparator)) {
		return "", "", errors.New("symbolic links outside the website root are not allowed")
	}
	return root, target, nil
}

func listManagedFilesEncoded(domain, path string) ([]managedFile, error) {
	root, target, err := managedSitePath(domain, path)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return nil, err
	}
	values := []managedFile{}
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		relative, _ := filepath.Rel(root, filepath.Join(target, entry.Name()))
		values = append(values, managedFile{Name: entry.Name(), Path: filepath.ToSlash(relative), Directory: entry.IsDir(), Size: info.Size(), Modified: info.ModTime().UTC().Format(time.RFC3339)})
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Directory != values[j].Directory {
			return values[i].Directory
		}
		return strings.ToLower(values[i].Name) < strings.ToLower(values[j].Name)
	})
	return values, nil
}

func readManagedFileEncoded(domain, path string) (fileContents, error) {
	root, target, err := managedSitePath(domain, path)
	if err != nil {
		return fileContents{}, err
	}
	info, err := os.Lstat(target)
	if err != nil {
		return fileContents{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fileContents{}, errors.New("only regular files can be opened")
	}
	if info.Size() > 2*1024*1024 {
		return fileContents{}, errors.New("text editor limit is 2 MB")
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		return fileContents{}, err
	}
	if strings.IndexByte(string(contents), 0) >= 0 {
		return fileContents{}, errors.New("binary files cannot be opened in the text editor")
	}
	relative, _ := filepath.Rel(root, target)
	return fileContents{Path: filepath.ToSlash(relative), Content: string(contents)}, nil
}

func writeManagedFileEncoded(domain, path, encodedContent string) (fileContents, error) {
	if os.Geteuid() != 0 {
		return fileContents{}, errors.New("file-write must run as root")
	}
	content, err := base64.RawURLEncoding.DecodeString(encodedContent)
	if err != nil {
		return fileContents{}, errors.New("invalid encoded content")
	}
	if len(content) > 2*1024*1024 {
		return fileContents{}, errors.New("text editor limit is 2 MB")
	}
	root, target, err := managedSitePath(domain, path)
	if err != nil {
		return fileContents{}, err
	}
	if target == root {
		return fileContents{}, errors.New("the website root cannot be overwritten")
	}
	if err := atomicWrite(target, content, 0644); err != nil {
		return fileContents{}, err
	}
	_ = writeAudit("file.updated", true, target)
	return readManagedFileEncoded(domain, path)
}

func deleteManagedFileEncoded(domain, path string) ([]managedFile, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("file-delete must run as root")
	}
	root, target, err := managedSitePath(domain, path)
	if err != nil {
		return nil, err
	}
	if target == root {
		return nil, errors.New("the website root cannot be deleted")
	}
	info, err := os.Lstat(target)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("symbolic links are not managed")
	}
	if err := os.Remove(target); err != nil {
		return nil, errors.New("only files and empty folders can be deleted")
	}
	_ = writeAudit("file.deleted", true, target)
	parent, _ := filepath.Rel(root, filepath.Dir(target))
	return listManagedFilesEncoded(domain, base64.RawURLEncoding.EncodeToString([]byte(parent)))
}

func installMailStack() (mailStatus, error) {
	if os.Geteuid() != 0 {
		return mailStatus{}, errors.New("mail-stack-install must run as root")
	}
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return mailStatus{}, errors.New("the server hostname is not configured")
	}
	command := exec.Command("apt-get", "install", "-y", "--no-install-recommends", "postfix", "dovecot-core", "dovecot-imapd", "dovecot-lmtpd")
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	output, err := command.CombinedOutput()
	if err != nil {
		return mailStatus{}, fmt.Errorf("install mail foundation: %s", tail(string(output), 1200))
	}
	for _, unit := range []string{"postfix", "dovecot"} {
		if output, err := exec.Command("systemctl", "enable", "--now", unit).CombinedOutput(); err != nil {
			return mailStatus{}, fmt.Errorf("start %s: %s", unit, tail(string(output), 800))
		}
	}
	_ = writeAudit("mail.stack.installed", true, hostname)
	return inspectMail()
}

func prepareDKIM(domain string) (dkimMaterial, error) {
	result := dkimMaterial{}
	if os.Geteuid() != 0 {
		return result, errors.New("mail-dkim-prepare must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) {
		return result, errors.New("invalid mail domain")
	}
	mail, err := inspectMail()
	if err != nil || !mail.ReadyForSetup {
		return result, errors.New("install and start the mail foundation first")
	}
	wasInstalled := packageVersion("opendkim") != ""
	if wasInstalled {
		if existing, readErr := os.ReadFile("/etc/opendkim.conf"); readErr == nil && !strings.Contains(string(existing), "Managed by ServerDeck") {
			return result, errors.New("an existing unmanaged OpenDKIM configuration was found; ServerDeck will not overwrite it")
		}
	} else {
		command := exec.Command("apt-get", "install", "-y", "--no-install-recommends", "opendkim", "opendkim-tools")
		command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if output, installErr := command.CombinedOutput(); installErr != nil {
			return result, fmt.Errorf("install OpenDKIM: %s", tail(string(output), 1200))
		}
	}
	keyDir := filepath.Join("/etc/opendkim/keys", domain)
	if err := os.MkdirAll(keyDir, 0750); err != nil {
		return result, err
	}
	privateKey := filepath.Join(keyDir, "mail.private")
	publicRecord := filepath.Join(keyDir, "mail.txt")
	if _, err := os.Stat(privateKey); os.IsNotExist(err) {
		if output, keyErr := exec.Command("opendkim-genkey", "-b", "2048", "-D", keyDir, "-d", domain, "-s", "mail").CombinedOutput(); keyErr != nil {
			return result, fmt.Errorf("generate DKIM key: %s", tail(string(output), 800))
		}
	}
	_ = os.Chmod(privateKey, 0600)
	if output, err := exec.Command("chown", "-R", "opendkim:opendkim", keyDir).CombinedOutput(); err != nil {
		return result, fmt.Errorf("protect DKIM keys: %s", tail(string(output), 500))
	}
	socketDir := "/var/spool/postfix/opendkim"
	if err := os.MkdirAll(socketDir, 0750); err != nil {
		return result, err
	}
	if output, err := exec.Command("chown", "opendkim:postfix", socketDir).CombinedOutput(); err != nil {
		return result, fmt.Errorf("prepare DKIM socket: %s", tail(string(output), 500))
	}
	config := "# Managed by ServerDeck\nSyslog yes\nUMask 007\nMode sv\nCanonicalization relaxed/simple\nSocket local:" + socketDir + "/opendkim.sock\nUserID opendkim\nKeyTable refile:/etc/opendkim/key.table\nSigningTable refile:/etc/opendkim/signing.table\nExternalIgnoreList refile:/etc/opendkim/trusted.hosts\nInternalHosts refile:/etc/opendkim/trusted.hosts\n"
	if err := atomicWrite("/etc/opendkim.conf", []byte(config), 0644); err != nil {
		return result, err
	}
	if err := atomicWrite("/etc/opendkim/key.table", []byte("mail._domainkey."+domain+" "+domain+":mail:"+privateKey+"\n"), 0644); err != nil {
		return result, err
	}
	if err := atomicWrite("/etc/opendkim/signing.table", []byte("*@"+domain+" mail._domainkey."+domain+"\n"), 0644); err != nil {
		return result, err
	}
	if err := atomicWrite("/etc/opendkim/trusted.hosts", []byte("127.0.0.1\n::1\nlocalhost\n"), 0644); err != nil {
		return result, err
	}
	mainCF, err := os.ReadFile("/etc/postfix/main.cf")
	if err != nil {
		return result, err
	}
	for _, setting := range []string{"milter_default_action=accept", "milter_protocol=6", "smtpd_milters=unix:opendkim/opendkim.sock", "non_smtpd_milters=unix:opendkim/opendkim.sock"} {
		if output, setErr := exec.Command("postconf", "-e", setting).CombinedOutput(); setErr != nil {
			_ = atomicWrite("/etc/postfix/main.cf", mainCF, 0644)
			return result, fmt.Errorf("configure Postfix DKIM: %s", tail(string(output), 500))
		}
	}
	rollback := func() {
		_ = atomicWrite("/etc/postfix/main.cf", mainCF, 0644)
		_ = exec.Command("systemctl", "restart", "postfix").Run()
	}
	if output, err := exec.Command("opendkim", "-n", "-x", "/etc/opendkim.conf").CombinedOutput(); err != nil {
		rollback()
		return result, fmt.Errorf("validate OpenDKIM: %s", tail(string(output), 800))
	}
	if output, err := exec.Command("postfix", "check").CombinedOutput(); err != nil {
		rollback()
		return result, fmt.Errorf("validate Postfix: %s", tail(string(output), 800))
	}
	if output, err := exec.Command("systemctl", "enable", "--now", "opendkim").CombinedOutput(); err != nil {
		rollback()
		return result, fmt.Errorf("start OpenDKIM: %s", tail(string(output), 800))
	}
	if output, err := exec.Command("systemctl", "restart", "postfix").CombinedOutput(); err != nil {
		rollback()
		return result, fmt.Errorf("restart Postfix: %s", tail(string(output), 800))
	}
	publicData, err := os.ReadFile(publicRecord)
	if err != nil {
		return result, err
	}
	parts := regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(string(publicData), -1)
	value := ""
	for _, part := range parts {
		if len(part) == 2 {
			value += part[1]
		}
	}
	if !strings.HasPrefix(value, "v=DKIM1;") {
		return result, errors.New("generated DKIM public record was invalid")
	}
	result = dkimMaterial{Domain: domain, Selector: "mail", Name: "mail._domainkey." + domain, Value: value}
	_ = writeAudit("mail.dkim.prepared", true, domain)
	return result, nil
}

func issueMailTLS(domain, email string) (mailTLSStatus, error) {
	result := mailTLSStatus{}
	if os.Geteuid() != 0 {
		return result, errors.New("mail-tls-issue must run as root")
	}
	domain, email = strings.ToLower(strings.TrimSpace(domain)), strings.TrimSpace(email)
	if !domainPattern.MatchString(domain) || !regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`).MatchString(email) {
		return result, errors.New("invalid mail domain or email")
	}
	mail, err := inspectMail()
	if err != nil || !mail.ReadyForSetup {
		return result, errors.New("install and start the mail foundation first")
	}
	hostname := "mail." + domain
	detected, err := detectPublicAddress()
	if err != nil {
		return result, err
	}
	publicIP := detected["address"]
	addresses, err := net.LookupIP(hostname)
	if err != nil {
		return result, fmt.Errorf("%s does not resolve in public DNS", hostname)
	}
	matched := false
	for _, address := range addresses {
		if address.String() == publicIP {
			matched = true
		}
	}
	if !matched {
		return result, fmt.Errorf("%s does not resolve to this server's public IP", hostname)
	}
	challengeRoot := "/var/lib/serverdeck/acme"
	if err := os.MkdirAll(filepath.Join(challengeRoot, ".well-known", "acme-challenge"), 0755); err != nil {
		return result, err
	}
	nginxPath := filepath.Join("/etc/nginx/sites-available", "serverdeck-mail-"+domain)
	enabledPath := filepath.Join("/etc/nginx/sites-enabled", "serverdeck-mail-"+domain)
	nginxConfig := fmt.Sprintf("# Managed by ServerDeck\nserver {\n listen 80;\n listen [::]:80;\n server_name %s;\n location /.well-known/acme-challenge/ { root %s; }\n location / { return 404; }\n}\n", hostname, challengeRoot)
	if existing, readErr := os.ReadFile(nginxPath); readErr == nil && !strings.Contains(string(existing), "Managed by ServerDeck") {
		return result, errors.New("an unmanaged Nginx configuration already uses the mail hostname")
	}
	if err := atomicWrite(nginxPath, []byte(nginxConfig), 0644); err != nil {
		return result, err
	}
	if _, err := os.Lstat(enabledPath); os.IsNotExist(err) {
		if err := os.Symlink(nginxPath, enabledPath); err != nil {
			return result, err
		}
	}
	if output, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		return result, fmt.Errorf("validate mail challenge: %s", tail(string(output), 800))
	}
	if err := exec.Command("systemctl", "reload", "nginx").Run(); err != nil {
		return result, err
	}
	arguments := []string{"certonly", "--webroot", "--webroot-path", challengeRoot, "--non-interactive", "--agree-tos", "--keep-until-expiring", "--email", email, "--domain", hostname}
	if output, err := exec.Command("certbot", arguments...).CombinedOutput(); err != nil {
		return result, fmt.Errorf("issue mail certificate: %s", tail(string(output), 1200))
	}
	certificateDir := filepath.Join("/etc/letsencrypt/live", hostname)
	certificate, privateKey := filepath.Join(certificateDir, "fullchain.pem"), filepath.Join(certificateDir, "privkey.pem")
	if _, err := os.Stat(certificate); err != nil {
		return result, errors.New("Certbot did not create the expected mail certificate")
	}
	mainCF, err := os.ReadFile("/etc/postfix/main.cf")
	if err != nil {
		return result, err
	}
	dovecotPath := "/etc/dovecot/conf.d/99-serverdeck-tls.conf"
	dovecotOriginal, dovecotReadErr := os.ReadFile(dovecotPath)
	rollback := func() {
		_ = atomicWrite("/etc/postfix/main.cf", mainCF, 0644)
		if dovecotReadErr == nil {
			_ = atomicWrite(dovecotPath, dovecotOriginal, 0644)
		} else {
			_ = os.Remove(dovecotPath)
		}
		_ = exec.Command("systemctl", "restart", "postfix").Run()
		_ = exec.Command("systemctl", "restart", "dovecot").Run()
	}
	for _, setting := range []string{"myhostname=" + hostname, "mydomain=" + domain, "myorigin=$mydomain", "smtpd_tls_cert_file=" + certificate, "smtpd_tls_key_file=" + privateKey, "smtpd_tls_security_level=may", "smtp_tls_security_level=may", "smtpd_tls_auth_only=yes"} {
		if output, setErr := exec.Command("postconf", "-e", setting).CombinedOutput(); setErr != nil {
			rollback()
			return result, fmt.Errorf("configure Postfix TLS: %s", tail(string(output), 800))
		}
	}
	versionOutput, _ := exec.Command("dovecot", "--version").Output()
	dovecotConfig := "# Managed by ServerDeck\nssl = required\n"
	if strings.HasPrefix(strings.TrimSpace(string(versionOutput)), "2.4") {
		dovecotConfig += "ssl_server_cert_file = " + certificate + "\nssl_server_key_file = " + privateKey + "\n"
	} else {
		dovecotConfig += "ssl_cert = <" + certificate + "\nssl_key = <" + privateKey + "\n"
	}
	if err := atomicWrite(dovecotPath, []byte(dovecotConfig), 0644); err != nil {
		rollback()
		return result, err
	}
	if output, err := exec.Command("postfix", "check").CombinedOutput(); err != nil {
		rollback()
		return result, fmt.Errorf("validate Postfix TLS: %s", tail(string(output), 800))
	}
	if output, err := exec.Command("doveconf", "-n").CombinedOutput(); err != nil {
		rollback()
		return result, fmt.Errorf("validate Dovecot TLS: %s", tail(string(output), 1000))
	}
	if output, err := exec.Command("systemctl", "restart", "postfix").CombinedOutput(); err != nil {
		rollback()
		return result, fmt.Errorf("restart Postfix: %s", tail(string(output), 800))
	}
	if output, err := exec.Command("systemctl", "restart", "dovecot").CombinedOutput(); err != nil {
		rollback()
		return result, fmt.Errorf("restart Dovecot: %s", tail(string(output), 800))
	}
	if err := atomicWrite("/etc/mailname", []byte(hostname+"\n"), 0644); err != nil {
		return result, err
	}
	_ = writeAudit("mail.tls.issued", true, hostname)
	return mailTLSStatus{Domain: domain, Hostname: hostname, Certificate: true, PostfixTLS: unitActive("postfix"), DovecotTLS: unitActive("dovecot")}, nil
}

func checkMailDNS(domain string) (mailDNSCheck, error) {
	result := mailDNSCheck{Records: []dnsRequirement{}}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) {
		return result, errors.New("invalid mail domain")
	}
	result.Domain = domain
	hostname := "mail." + domain
	detected, err := detectPublicAddress()
	if err != nil {
		return result, err
	}
	publicIP := detected["address"]
	addresses, _ := net.LookupIP(hostname)
	aPresent := false
	for _, address := range addresses {
		if address.String() == publicIP {
			aPresent = true
		}
	}
	result.Records = append(result.Records, dnsRequirement{Type: "A", Name: hostname, Value: publicIP, Present: aPresent, Note: "Must be DNS-only, not proxied"})
	matchesMX := false
	if values, lookupErr := net.LookupMX(domain); lookupErr == nil {
		for _, value := range values {
			if strings.TrimSuffix(strings.ToLower(value.Host), ".") == hostname {
				matchesMX = true
			}
		}
	}
	result.Records = append(result.Records, dnsRequirement{Type: "MX", Name: domain, Value: "10 " + hostname, Present: matchesMX, Note: "Priority 10"})
	spfValue := "v=spf1 a:" + hostname + " mx ~all"
	spfPresent := false
	if values, lookupErr := net.LookupTXT(domain); lookupErr == nil {
		for _, value := range values {
			lower := strings.ToLower(value)
			if strings.HasPrefix(lower, "v=spf1") && strings.Contains(lower, "a:"+hostname) {
				spfPresent = true
			}
		}
	}
	result.Records = append(result.Records, dnsRequirement{Type: "TXT", Name: domain, Value: spfValue, Present: spfPresent, Note: "Merge with an existing SPF policy; never publish two SPF records"})
	dmarcValue := "v=DMARC1; p=none"
	dmarcPresent := false
	if values, lookupErr := net.LookupTXT("_dmarc." + domain); lookupErr == nil {
		for _, value := range values {
			if strings.HasPrefix(strings.ToUpper(value), "V=DMARC1;") {
				dmarcPresent = true
			}
		}
	}
	result.Records = append(result.Records, dnsRequirement{Type: "TXT", Name: "_dmarc." + domain, Value: dmarcValue, Present: dmarcPresent, Note: "Start in monitoring mode; tighten after delivery is verified"})
	dkimName := "mail._domainkey." + domain
	dkimValue := "Generate DKIM in ServerDeck first"
	if publicData, readErr := os.ReadFile(filepath.Join("/etc/opendkim/keys", domain, "mail.txt")); readErr == nil {
		parts := regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(string(publicData), -1)
		value := ""
		for _, part := range parts {
			if len(part) == 2 {
				value += part[1]
			}
		}
		if strings.HasPrefix(value, "v=DKIM1;") {
			dkimValue = value
		}
	}
	dkimPresent := false
	if dkimValue != "Generate DKIM in ServerDeck first" {
		if values, lookupErr := net.LookupTXT(dkimName); lookupErr == nil {
			normalized := strings.ReplaceAll(dkimValue, " ", "")
			for _, value := range values {
				if strings.ReplaceAll(value, " ", "") == normalized {
					dkimPresent = true
				}
			}
		}
	}
	result.Records = append(result.Records, dnsRequirement{Type: "TXT", Name: dkimName, Value: dkimValue, Present: dkimPresent, Note: "Public key only; the private key never leaves the server"})
	return result, nil
}

func packageCandidate(name string) string {
	output, _ := exec.Command("apt-cache", "policy", name).Output()
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Candidate:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
			if value != "(none)" {
				return value
			}
		}
	}
	return ""
}

func unitActive(name string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", name).Run() == nil
}

func listSoftware() ([]softwarePackage, error) {
	dockerPackage := "docker.io"
	dockerDescription := "Ubuntu-maintained container runtime"
	if packageCandidate("docker-ce") != "" {
		dockerPackage = "docker-ce"
		dockerDescription = "Docker Engine from Docker's official repository"
	}
	catalog := []softwarePackage{
		{ID: "nginx", Name: "Nginx", Category: "Web", Package: "nginx", Description: "Web server and reverse proxy"},
		{ID: "apache2", Name: "Apache", Category: "Web", Package: "apache2", Description: "Alternative web server"},
		{ID: "mariadb", Name: "MariaDB", Category: "Database", Package: "mariadb-server", Description: "Relational database server"},
		{ID: "mysql", Name: "MySQL", Category: "Database", Package: "mysql-server", Description: "MySQL database server"},
		{ID: "postgresql", Name: "PostgreSQL", Category: "Database", Package: "postgresql", Description: "Relational database server"},
		{ID: "redis", Name: "Redis", Category: "Database", Package: "redis-server", Description: "In-memory cache and data store"},
		{ID: "nodejs", Name: "Node.js", Category: "Runtime", Package: "nodejs", Description: "JavaScript runtime"},
		{ID: "vsftpd", Name: "vsftpd", Category: "File Transfer", Package: "vsftpd", Description: "Optional legacy FTP server; SFTP is preferred"},
		{ID: "docker", Name: "Docker", Category: "Containers", Package: dockerPackage, Description: dockerDescription},
		{ID: "postfix", Name: "Postfix", Category: "Email", Package: "postfix", Description: "Mail transfer agent"},
		{ID: "dovecot", Name: "Dovecot", Category: "Email", Package: "dovecot-core", Description: "IMAP and POP3 server"},
		{ID: "fail2ban", Name: "Fail2ban", Category: "Security", Package: "fail2ban", Description: "Intrusion prevention"},
		{ID: "ufw", Name: "UFW", Category: "Security", Package: "ufw", Description: "Host firewall"},
		{ID: "certbot", Name: "Certbot", Category: "Utilities", Package: "certbot", Description: "Let's Encrypt certificate client"},
		{ID: "git", Name: "Git", Category: "Utilities", Package: "git", Description: "Source control client"},
	}
	units := map[string]string{"nginx": "nginx", "apache2": "apache2", "mariadb": "mariadb", "mysql": "mysql", "postgresql": "postgresql", "redis": "redis-server", "vsftpd": "vsftpd", "docker": "docker", "postfix": "postfix", "dovecot": "dovecot", "fail2ban": "fail2ban", "ufw": "ufw"}
	for index := range catalog {
		catalog[index].Version = packageVersion(catalog[index].Package)
		catalog[index].Installed = catalog[index].Version != ""
		catalog[index].Candidate = packageCandidate(catalog[index].Package)
		if unit, ok := units[catalog[index].ID]; ok {
			catalog[index].Active = unitActive(unit)
		}
	}
	return catalog, nil
}

func listPackageSources() ([]packageSource, error) {
	paths := []string{"/etc/apt/sources.list"}
	additional, _ := filepath.Glob("/etc/apt/sources.list.d/*")
	paths = append(paths, additional...)
	values := []packageSource{}
	for _, path := range paths {
		info, statErr := os.Stat(path)
		if statErr != nil || info.IsDir() || (!strings.HasSuffix(path, ".list") && !strings.HasSuffix(path, ".sources") && path != "/etc/apt/sources.list") {
			continue
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		if strings.HasSuffix(path, ".sources") {
			stanzas := regexp.MustCompile(`\n\s*\n`).Split(string(contents), -1)
			for _, stanza := range stanzas {
				fields := map[string]string{}
				for _, line := range strings.Split(stanza, "\n") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						fields[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
				enabled := strings.ToLower(fields["Enabled"]) != "no"
				for _, uri := range strings.Fields(fields["URIs"]) {
					values = append(values, newPackageSource(path, uri, fields["Suites"], fields["Signed-By"], enabled))
				}
			}
			continue
		}
		for _, rawLine := range strings.Split(string(contents), "\n") {
			line := strings.TrimSpace(rawLine)
			enabled := true
			if strings.HasPrefix(line, "#") {
				enabled = false
				line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			}
			if !strings.HasPrefix(line, "deb ") {
				continue
			}
			signedBy := ""
			if match := regexp.MustCompile(`signed-by=([^\] ]+)`).FindStringSubmatch(line); len(match) == 2 {
				signedBy = match[1]
			}
			line = regexp.MustCompile(`^deb\s+(\[[^\]]+\]\s+)?`).ReplaceAllString(line, "")
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				suite := ""
				if len(parts) >= 2 {
					suite = parts[1]
				}
				values = append(values, newPackageSource(path, parts[0], suite, signedBy, enabled))
			}
		}
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Official != values[j].Official {
			return values[i].Official
		}
		return values[i].URI < values[j].URI
	})
	return values, nil
}

func newPackageSource(path, uri, suite, signedBy string, enabled bool) packageSource {
	hash := sha256.Sum256([]byte(path + "\x00" + uri + "\x00" + suite))
	official := strings.Contains(uri, "archive.ubuntu.com") || strings.Contains(uri, "security.ubuntu.com") || strings.Contains(uri, "ports.ubuntu.com")
	return packageSource{
		ID:       fmt.Sprintf("%x", hash[:8]),
		File:     path,
		URI:      uri,
		Suite:    suite,
		Official: official,
		SignedBy: signedBy,
		Enabled:  enabled,
	}
}

func ubuntuCodename() string {
	contents, _ := os.ReadFile("/etc/os-release")
	for _, line := range strings.Split(string(contents), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && (parts[0] == "UBUNTU_CODENAME" || parts[0] == "VERSION_CODENAME") {
			return strings.Trim(parts[1], "\"")
		}
	}
	return ""
}

func packageSourceCatalog() ([]sourceCatalogItem, error) {
	codename := ubuntuCodename()
	sources, err := listPackageSources()
	if err != nil {
		return nil, err
	}
	hasURI := func(fragment string) bool {
		for _, source := range sources {
			if source.Enabled && strings.Contains(source.URI, fragment) {
				return true
			}
		}
		return false
	}
	phpSupported := codename == "jammy" || codename == "noble"
	dockerSupported := codename == "jammy" || codename == "noble" || codename == "questing" || codename == "resolute"
	phpReason := ""
	if !phpSupported {
		phpReason = "Available only for currently supported Ubuntu LTS releases (22.04 and 24.04)"
	}
	dockerReason := ""
	if !dockerSupported {
		dockerReason = "Docker does not list this Ubuntu release as supported"
	}
	return []sourceCatalogItem{
		{ID: "ondrej-php", Name: "PHP versions by Ondřej Surý", Description: "Co-installable PHP versions for current Ubuntu LTS releases", Supported: phpSupported, Enabled: hasURI("ppa.launchpadcontent.net/ondrej/php"), Reason: phpReason},
		{ID: "docker", Name: "Docker official", Description: "Docker Engine, Compose, Buildx, and containerd packages", Supported: dockerSupported, Enabled: hasURI("download.docker.com/linux/ubuntu"), Reason: dockerReason},
		{ID: "nodesource", Name: "NodeSource", Description: "Additional Node.js release lines", Supported: false, Enabled: hasURI("deb.nodesource.com"), Reason: "Temporarily unavailable while upstream signing and repository reliability issues are reviewed"},
	}, nil
}

func enablePackageSource(id string) ([]sourceCatalogItem, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("source-enable must run as root")
	}
	codename := ubuntuCodename()
	if output, err := exec.Command("apt-get", "update").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("refresh package information: %s", tail(string(output), 800))
	}
	if output, err := exec.Command("apt-get", "install", "-y", "--no-install-recommends", "ca-certificates", "gnupg").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("install repository prerequisites: %s", tail(string(output), 800))
	}
	if err := os.MkdirAll("/etc/apt/keyrings", 0755); err != nil {
		return nil, err
	}
	created := []string{}
	rollback := func() {
		for _, path := range created {
			_ = os.Remove(path)
		}
	}
	switch id {
	case "ondrej-php":
		if codename != "jammy" && codename != "noble" {
			return nil, errors.New("the PHP PPA supports Ubuntu 22.04 and 24.04 only")
		}
		keyData, err := downloadRepositoryFile("https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6")
		if err != nil {
			return nil, err
		}
		temporary, err := os.CreateTemp("", "serverdeck-php-key-*")
		if err != nil {
			return nil, err
		}
		temporaryPath := temporary.Name()
		defer os.Remove(temporaryPath)
		if _, err = temporary.Write(keyData); err != nil {
			temporary.Close()
			return nil, err
		}
		temporary.Close()
		fingerprints, err := exec.Command("gpg", "--batch", "--show-keys", "--with-colons", temporaryPath).Output()
		if err != nil || !strings.Contains(string(fingerprints), "B8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6") {
			return nil, errors.New("PHP repository signing key fingerprint did not match the verified fingerprint")
		}
		keyPath := "/etc/apt/keyrings/serverdeck-ondrej-php.gpg"
		if output, err := exec.Command("gpg", "--batch", "--yes", "--dearmor", "--output", keyPath, temporaryPath).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("store PHP repository key: %s", tail(string(output), 800))
		}
		created = append(created, keyPath)
		sourcePath := "/etc/apt/sources.list.d/serverdeck-ondrej-php.sources"
		source := fmt.Sprintf("Types: deb\nURIs: https://ppa.launchpadcontent.net/ondrej/php/ubuntu\nSuites: %s\nComponents: main\nSigned-By: %s\n", codename, keyPath)
		if err := atomicWrite(sourcePath, []byte(source), 0644); err != nil {
			rollback()
			return nil, err
		}
		created = append(created, sourcePath)
	case "docker":
		allowed := codename == "jammy" || codename == "noble" || codename == "questing" || codename == "resolute"
		if !allowed {
			return nil, errors.New("Docker does not list this Ubuntu release as supported")
		}
		keyData, err := downloadRepositoryFile("https://download.docker.com/linux/ubuntu/gpg")
		if err != nil {
			return nil, err
		}
		keyPath := "/etc/apt/keyrings/docker.asc"
		if err := atomicWrite(keyPath, keyData, 0644); err != nil {
			return nil, err
		}
		created = append(created, keyPath)
		architectureData, architectureErr := exec.Command("dpkg", "--print-architecture").Output()
		if architectureErr != nil {
			rollback()
			return nil, errors.New("could not determine package architecture")
		}
		architecture := strings.TrimSpace(string(architectureData))
		sourcePath := "/etc/apt/sources.list.d/docker.sources"
		source := fmt.Sprintf("Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: %s\n", codename, architecture, keyPath)
		if err := atomicWrite(sourcePath, []byte(source), 0644); err != nil {
			rollback()
			return nil, err
		}
		created = append(created, sourcePath)
	default:
		return nil, errors.New("source is not available in the verified ServerDeck catalog")
	}
	if output, err := exec.Command("apt-get", "update").CombinedOutput(); err != nil {
		rollback()
		return nil, fmt.Errorf("verify repository: %s", tail(string(output), 1000))
	}
	_ = writeAudit("source.enable.completed", true, id)
	return packageSourceCatalog()
}

func downloadRepositoryFile(address string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Get(address)
	if err != nil {
		return nil, fmt.Errorf("download repository key: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("download repository key: HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("repository key download was empty")
	}
	return data, nil
}

func installCatalogSoftware(id string) ([]softwarePackage, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("software-install must run as root")
	}
	catalog := map[string]struct {
		packages []string
		unit     string
	}{
		"nginx":      {[]string{"nginx"}, "nginx"},
		"apache2":    {[]string{"apache2"}, "apache2"},
		"mariadb":    {[]string{"mariadb-server"}, "mariadb"},
		"mysql":      {[]string{"mysql-server"}, "mysql"},
		"postgresql": {[]string{"postgresql"}, "postgresql"},
		"redis":      {[]string{"redis-server"}, "redis-server"},
		"nodejs":     {[]string{"nodejs", "npm"}, ""},
		"vsftpd":     {[]string{"vsftpd"}, "vsftpd"},
		"docker":     {[]string{"docker.io"}, "docker"},
		"postfix":    {[]string{"postfix"}, "postfix"},
		"dovecot":    {[]string{"dovecot-core", "dovecot-imapd"}, "dovecot"},
		"fail2ban":   {[]string{"fail2ban"}, "fail2ban"},
		"ufw":        {[]string{"ufw"}, ""},
		"certbot":    {[]string{"certbot"}, ""},
		"git":        {[]string{"git"}, ""},
	}
	if packageCandidate("docker-ce") != "" {
		catalog["docker"] = struct {
			packages []string
			unit     string
		}{[]string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}, "docker"}
	}
	selection, ok := catalog[id]
	if !ok {
		return nil, errors.New("software is not in the verified ServerDeck catalog")
	}
	if id == "postfix" || id == "dovecot" {
		return nil, errors.New("mail components must be installed together through ServerDeck Email setup")
	}
	if id == "nginx" && packageVersion("apache2") != "" {
		return nil, errors.New("Apache is already installed; migrate or remove it before installing Nginx")
	}
	if id == "apache2" && packageVersion("nginx") != "" {
		return nil, errors.New("Nginx is already installed; migrate or remove it before installing Apache")
	}
	if id == "mariadb" && packageVersion("mysql-server") != "" {
		return nil, errors.New("MySQL is already installed; MariaDB cannot be installed beside it safely")
	}
	if id == "mysql" && packageVersion("mariadb-server") != "" {
		return nil, errors.New("MariaDB is already installed; MySQL cannot be installed beside it safely")
	}
	if id == "postgresql" && (packageVersion("mariadb-server") != "" || packageVersion("mysql-server") != "") {
		return nil, errors.New("A MySQL-compatible database is already installed; ServerDeck manages one database engine per server")
	}
	if (id == "mariadb" || id == "mysql") && packageVersion("postgresql") != "" {
		return nil, errors.New("PostgreSQL is already installed; ServerDeck manages one database engine per server")
	}
	if id == "docker" && packageCandidate("docker-ce") != "" && packageVersion("docker.io") != "" {
		return nil, errors.New("Ubuntu docker.io is already installed; migrate it before installing Docker Engine from the official source")
	}
	if err := writeAudit("software.install.started", true, id); err != nil {
		return nil, err
	}
	if output, err := exec.Command("apt-get", "update").CombinedOutput(); err != nil {
		_ = writeAudit("software.install.failed", false, id+": "+tail(string(output), 800))
		return nil, fmt.Errorf("refresh package information: %s", tail(string(output), 800))
	}
	arguments := append([]string{"install", "-y", "--no-install-recommends"}, selection.packages...)
	if output, err := exec.Command("apt-get", arguments...).CombinedOutput(); err != nil {
		_ = writeAudit("software.install.failed", false, id+": "+tail(string(output), 800))
		return nil, fmt.Errorf("install %s: %s", id, tail(string(output), 800))
	}
	if selection.unit != "" {
		if output, err := exec.Command("systemctl", "enable", "--now", selection.unit).CombinedOutput(); err != nil {
			_ = writeAudit("software.install.failed", false, id+": "+tail(string(output), 800))
			return nil, fmt.Errorf("enable %s: %s", selection.unit, tail(string(output), 800))
		}
	}
	_ = writeAudit("software.install.completed", true, id)
	return listSoftware()
}

func planSoftwareRemoval(id string) (softwareRemovalPlan, error) {
	names := map[string]string{"nginx": "Nginx", "apache2": "Apache", "mariadb": "MariaDB", "mysql": "MySQL", "postgresql": "PostgreSQL", "redis": "Redis", "nodejs": "Node.js", "vsftpd": "vsftpd", "docker": "Docker", "postfix": "Postfix", "dovecot": "Dovecot", "fail2ban": "Fail2ban", "ufw": "UFW", "certbot": "Certbot", "git": "Git"}
	name, known := names[id]
	if !known {
		return softwareRemovalPlan{}, errors.New("software is not in the verified ServerDeck catalog")
	}
	plan := softwareRemovalPlan{ID: id, Name: name, Allowed: true, Reason: "No managed dependency was found", Affected: []string{}}
	sites, _ := listSites()
	databases, _ := listDatabases()
	switch id {
	case "nginx", "apache2":
		webServer := map[string]string{"nginx": "nginx", "apache2": "apache"}[id]
		for _, item := range sites {
			itemServer := item.WebServer
			if itemServer == "" { itemServer = "nginx" }
			if itemServer == webServer { plan.Affected = append(plan.Affected, item.Domain) }
		}
	case "nodejs":
		for _, item := range sites { if item.Kind == "node" { plan.Affected = append(plan.Affected, item.Domain) } }
	case "mariadb", "mysql", "postgresql":
		engine := map[string]string{"mariadb": "MariaDB", "mysql": "MySQL", "postgresql": "PostgreSQL"}[id]
		for _, item := range databases {
			itemEngine := item.Engine
			if itemEngine == "" { itemEngine = "MariaDB" }
			if itemEngine == engine { plan.Affected = append(plan.Affected, item.Name) }
		}
	case "docker":
		inventory, _ := inspectContainers()
		for _, item := range inventory.Containers { plan.Affected = append(plan.Affected, item.Name) }
	case "certbot":
		statuses, _ := listTLS()
		for _, item := range statuses { if item.Certificate { plan.Affected = append(plan.Affected, item.Domain) } }
	case "postfix", "dovecot":
		plan.Allowed = false
		plan.Reason = "Mail components must be removed through a coordinated Email teardown workflow"
	case "ufw":
		plan.Allowed = false
		plan.Reason = "Disable the firewall from Security; removing the firewall package is intentionally unavailable"
	}
	if len(plan.Affected) > 0 {
		plan.Allowed = false
		plan.Reason = fmt.Sprintf("%d managed item(s) still depend on %s", len(plan.Affected), name)
	}
	return plan, nil
}

func removeCatalogSoftware(id string) ([]softwarePackage, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("software-remove must run as root")
	}
	plan, err := planSoftwareRemoval(id)
	if err != nil { return nil, err }
	if !plan.Allowed { return nil, errors.New(plan.Reason) }
	packages := map[string][]string{
		"nginx": {"nginx"}, "apache2": {"apache2"}, "mariadb": {"mariadb-server"}, "mysql": {"mysql-server"},
		"postgresql": {"postgresql"}, "redis": {"redis-server"}, "nodejs": {"nodejs", "npm"}, "vsftpd": {"vsftpd"},
		"docker": {"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"},
		"fail2ban": {"fail2ban"}, "certbot": {"certbot"}, "git": {"git"},
	}
	selection, ok := packages[id]
	if !ok { return nil, errors.New("this software must be managed from its dedicated section") }
	if id == "docker" && packageVersion("docker-ce") == "" { selection = []string{"docker.io"} }
	_ = writeAudit("software.remove.started", true, id)
	arguments := append([]string{"remove", "-y"}, selection...)
	if output, err := exec.Command("apt-get", arguments...).CombinedOutput(); err != nil {
		_ = writeAudit("software.remove.failed", false, id+": "+tail(string(output), 800))
		return nil, fmt.Errorf("remove %s: %s", id, tail(string(output), 800))
	}
	_ = writeAudit("software.remove.completed", true, id)
	return listSoftware()
}

func listPHPVersions() ([]phpVersionStatus, error) {
	sites, err := listSites()
	if err != nil {
		return nil, err
	}
	versions := []phpVersionStatus{}
	for major := 7; major <= 8; major++ {
		start, end := 0, 5
		if major == 7 {
			start = 4
			end = 4
		}
		for minor := start; minor <= end; minor++ {
			version := fmt.Sprintf("%d.%d", major, minor)
			base := "php" + version
			installed := packageVersion(base+"-fpm") != ""
			available := packageCandidate(base+"-fpm") != ""
			if !installed && !available {
				continue
			}
			value := phpVersionStatus{Version: version, Installed: installed, Available: available, Active: unitActive(base + "-fpm"), Extensions: []string{}, UsedBy: []string{}}
			for _, extension := range []string{"bcmath", "curl", "gd", "intl", "mbstring", "mysql", "opcache", "soap", "xml", "zip"} {
				if packageVersion(base+"-"+extension) != "" {
					value.Extensions = append(value.Extensions, extension)
				}
			}
			for _, site := range sites {
				if site.PHPVersion == version {
					value.UsedBy = append(value.UsedBy, site.Domain)
				}
			}
			versions = append(versions, value)
		}
	}
	return versions, nil
}

func installPHPVersion(version string) ([]phpVersionStatus, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("php-version-install must run as root")
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) {
		return nil, errors.New("invalid PHP version")
	}
	base := "php" + version
	if packageCandidate(base+"-fpm") == "" {
		return nil, errors.New("this PHP version is not available from the server's configured repositories")
	}
	packages := []string{base + "-fpm", base + "-cli", base + "-common", base + "-curl", base + "-mbstring", base + "-mysql", base + "-xml", base + "-zip", base + "-opcache"}
	arguments := append([]string{"install", "-y", "--no-install-recommends"}, packages...)
	output, err := exec.Command("apt-get", arguments...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("install PHP %s: %s", version, tail(string(output), 1200))
	}
	if err := exec.Command("systemctl", "enable", "--now", base+"-fpm").Run(); err != nil {
		return nil, fmt.Errorf("start PHP %s FPM: %w", version, err)
	}
	_ = writeAudit("software.php.installed", true, version)
	return listPHPVersions()
}

func removePHPVersion(version string) ([]phpVersionStatus, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("php-version-remove must run as root")
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) {
		return nil, errors.New("invalid PHP version")
	}
	sites, err := listSites()
	if err != nil {
		return nil, err
	}
	usedBy := []string{}
	for _, site := range sites {
		if site.PHPVersion == version {
			usedBy = append(usedBy, site.Domain)
		}
	}
	if len(usedBy) > 0 {
		return nil, fmt.Errorf("PHP %s is still used by: %s", version, strings.Join(usedBy, ", "))
	}
	base := "php" + version
	packages := []string{}
	for _, suffix := range []string{"-fpm", "-cli", "-common", "-curl", "-mbstring", "-mysql", "-xml", "-zip", "-opcache", "-readline"} {
		name := base + suffix
		if packageVersion(name) != "" {
			packages = append(packages, name)
		}
	}
	if len(packages) == 0 {
		return listPHPVersions()
	}
	arguments := append([]string{"remove", "-y"}, packages...)
	output, err := exec.Command("apt-get", arguments...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("remove PHP %s: %s", version, tail(string(output), 1200))
	}
	_ = writeAudit("software.php.removed", true, version)
	return listPHPVersions()
}

func setPHPExtension(version, extension, action string) ([]phpVersionStatus, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("php-extension-set must run as root")
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) {
		return nil, errors.New("invalid PHP version")
	}
	allowed := map[string]bool{"curl": true, "mbstring": true, "mysql": true, "xml": true, "zip": true, "opcache": true, "gd": true, "intl": true, "bcmath": true, "soap": true}
	if !allowed[extension] {
		return nil, errors.New("unsupported PHP extension")
	}
	if action != "install" && action != "remove" {
		return nil, errors.New("extension action must be install or remove")
	}
	base := "php" + version
	if packageVersion(base+"-fpm") == "" {
		return nil, errors.New("install this PHP version before managing extensions")
	}
	packageName := base + "-" + extension
	if action == "install" && packageCandidate(packageName) == "" {
		return nil, errors.New("this extension is not available from the configured repositories")
	}
	output, err := exec.Command("apt-get", action, "-y", "--no-install-recommends", packageName).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %s", action, packageName, tail(string(output), 1200))
	}
	if err := exec.Command("systemctl", "restart", base+"-fpm").Run(); err != nil {
		return nil, fmt.Errorf("restart PHP %s FPM: %w", version, err)
	}
	_ = writeAudit("software.php.extension."+action, true, version+" "+extension)
	return listPHPVersions()
}

func listRuntimes() (runtimes, error) {
	result := runtimes{PHP: []phpRuntime{}, Node: []string{}}
	sockets, _ := filepath.Glob("/run/php/php[0-9]*-fpm.sock")
	sort.Strings(sockets)
	for _, socket := range sockets {
		version := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(socket), "php"), "-fpm.sock")
		result.PHP = append(result.PHP, phpRuntime{Version: version, Socket: socket, Active: true})
	}
	if output, err := exec.Command("node", "--version").Output(); err == nil {
		result.Node = append(result.Node, strings.TrimPrefix(strings.TrimSpace(string(output)), "v"))
	}
	return result, nil
}

func switchPHP(domain, version string) (site, error) {
	value := site{}
	if os.Geteuid() != 0 {
		return value, errors.New("site-switch-php must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) || !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) {
		return value, errors.New("invalid domain or PHP version")
	}
	metadataPath := filepath.Join("/var/lib/serverdeck/sites", domain+".json")
	metadata, err := os.ReadFile(metadataPath)
	if err != nil {
		return value, errors.New("managed site was not found")
	}
	if err := json.Unmarshal(metadata, &value); err != nil {
		return value, err
	}
	if value.Kind != "php" {
		return value, errors.New("only PHP sites can switch PHP runtimes")
	}
	socket := "/run/php/php" + version + "-fpm.sock"
	if _, err := os.Stat(socket); err != nil {
		return value, errors.New("selected PHP-FPM version is not active")
	}
	webServer := value.WebServer
	if webServer == "" {
		webServer = "nginx"
	}
	configPath := filepath.Join("/etc/nginx/sites-available", domain)
	if webServer == "apache" {
		configPath = filepath.Join("/etc/apache2/sites-available", domain+".conf")
	}
	original, err := os.ReadFile(configPath)
	if err != nil {
		return value, err
	}
	updated := regexp.MustCompile(`fastcgi_pass unix:[^;]+;`).ReplaceAll(original, []byte("fastcgi_pass unix:"+socket+";"))
	if webServer == "apache" {
		updated = regexp.MustCompile(`proxy:unix:[^|]+\|fcgi://localhost/`).ReplaceAll(original, []byte("proxy:unix:"+socket+"|fcgi://localhost/"))
	}
	if err := atomicWrite(configPath, updated, 0644); err != nil {
		return value, err
	}
	rollback := func() {
		_ = atomicWrite(configPath, original, 0644)
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
	value.PHPVersion = version
	encoded, _ := json.MarshalIndent(value, "", "  ")
	if err := atomicWrite(metadataPath, append(encoded, '\n'), 0644); err != nil {
		rollback()
		return site{}, err
	}
	_ = writeAudit("site.php.switched", true, domain+" -> PHP "+version)
	return value, nil
}

func installNode() (map[string]interface{}, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("node-install must run as root")
	}
	if output, err := exec.Command("apt-get", "install", "-y", "--no-install-recommends", "nodejs", "npm").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("Node.js installation failed: %s", tail(string(output), 800))
	}
	version, _ := exec.Command("node", "--version").Output()
	_ = writeAudit("runtime.node.installed", true, strings.TrimSpace(string(version)))
	return map[string]interface{}{"version": strings.TrimPrefix(strings.TrimSpace(string(version)), "v")}, nil
}

func createNodeProject(domain string) (site, error) {
	value := site{}
	if os.Geteuid() != 0 {
		return value, errors.New("project-create must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) {
		return value, errors.New("invalid domain name")
	}
	if _, err := exec.LookPath("node"); err != nil {
		return value, errors.New("Node.js is not installed")
	}
	webServer := ""
	if packageVersion("nginx") != "" && unitActive("nginx") {
		webServer = "nginx"
	} else if packageVersion("apache2") != "" && unitActive("apache2") {
		webServer = "apache"
	} else {
		return value, errors.New("Nginx or Apache must be installed and running")
	}
	metadataPath := filepath.Join("/var/lib/serverdeck/sites", domain+".json")
	if _, err := os.Stat(metadataPath); err == nil {
		return value, errors.New("a managed site with this domain already exists")
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(domain)))
	user, serviceName := "sd-"+hash[:12], "serverdeck-"+hash[:12]
	port := 3200 + int(hash[0])
	root := filepath.Join("/var/www", domain, "app")
	if err := os.MkdirAll(root, 0750); err != nil {
		return value, err
	}
	if err := exec.Command("useradd", "--system", "--home", root, "--shell", "/usr/sbin/nologin", user).Run(); err != nil {
		return value, fmt.Errorf("create service user: %w", err)
	}
	serverJS := fmt.Sprintf("const http=require('http');const port=process.env.PORT||%d;http.createServer((req,res)=>res.end('<h1>%s</h1><p>Node.js managed by ServerDeck.</p>')).listen(port,'127.0.0.1');\n", port, domain)
	if err := os.WriteFile(filepath.Join(root, "server.js"), []byte(serverJS), 0640); err != nil {
		return value, err
	}
	_ = exec.Command("chown", "-R", user+":"+user, filepath.Dir(root)).Run()
	versionOutput, _ := exec.Command("node", "--version").Output()
	nodeVersion := strings.TrimPrefix(strings.TrimSpace(string(versionOutput)), "v")
	unit := fmt.Sprintf("[Unit]\nDescription=ServerDeck Node project %s\nAfter=network.target\n\n[Service]\nUser=%s\nGroup=%s\nWorkingDirectory=%s\nEnvironment=PORT=%d\nExecStart=/usr/bin/node server.js\nRestart=on-failure\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nReadWritePaths=%s\n\n[Install]\nWantedBy=multi-user.target\n", domain, user, user, root, port, root)
	unitPath := filepath.Join("/etc/systemd/system", serviceName+".service")
	if err := atomicWrite(unitPath, []byte(unit), 0644); err != nil {
		return value, err
	}
	config := fmt.Sprintf("server {\n listen 80;\n listen [::]:80;\n server_name %s;\n location / {\n  proxy_pass http://127.0.0.1:%d;\n  proxy_set_header Host $host;\n  proxy_set_header X-Real-IP $remote_addr;\n  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n  proxy_set_header X-Forwarded-Proto $scheme;\n }\n}\n", domain, port)
	configPath, enabledPath := filepath.Join("/etc/nginx/sites-available", domain), filepath.Join("/etc/nginx/sites-enabled", domain)
	if webServer == "apache" {
		if output, err := exec.Command("a2enmod", "proxy", "proxy_http", "headers").CombinedOutput(); err != nil {
			return value, fmt.Errorf("enable Apache proxy modules: %s", tail(string(output), 800))
		}
		config = fmt.Sprintf("<VirtualHost *:80>\n ServerName %s\n ProxyPreserveHost On\n ProxyPass / http://127.0.0.1:%d/\n ProxyPassReverse / http://127.0.0.1:%d/\n RequestHeader set X-Forwarded-Proto expr=%%{REQUEST_SCHEME}\n</VirtualHost>\n", domain, port, port)
		configPath = filepath.Join("/etc/apache2/sites-available", domain+".conf")
		enabledPath = filepath.Join("/etc/apache2/sites-enabled", domain+".conf")
	}
	if err := atomicWrite(configPath, []byte(config), 0644); err != nil {
		return value, err
	}
	if webServer == "nginx" {
		if err := os.Symlink(configPath, enabledPath); err != nil {
			return value, err
		}
	} else if output, err := exec.Command("a2ensite", domain+".conf").CombinedOutput(); err != nil {
		return value, fmt.Errorf("enable Apache site: %s", tail(string(output), 800))
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	if output, err := exec.Command("systemctl", "enable", "--now", serviceName).CombinedOutput(); err != nil {
		return value, fmt.Errorf("start project: %s", tail(string(output), 800))
	}
	validation := exec.Command("nginx", "-t")
	if webServer == "apache" {
		validation = exec.Command("apache2ctl", "configtest")
	}
	if output, err := validation.CombinedOutput(); err != nil {
		return value, fmt.Errorf("%s validation failed: %s", webServer, tail(string(output), 800))
	}
	if err := exec.Command("systemctl", "reload", map[string]string{"nginx": "nginx", "apache": "apache2"}[webServer]).Run(); err != nil {
		return value, err
	}
	value = site{Domain: domain, Kind: "node", Root: root, Enabled: true, NodeVersion: nodeVersion, Service: serviceName, Port: port, CreatedAt: time.Now().UTC().Format(time.RFC3339), WebServer: webServer}
	encoded, _ := json.MarshalIndent(value, "", "  ")
	if err := atomicWrite(metadataPath, append(encoded, '\n'), 0644); err != nil {
		return site{}, err
	}
	_ = writeAudit("project.node.created", true, domain+" Node "+nodeVersion)
	return value, nil
}

func listSites() ([]site, error) {
	paths, err := filepath.Glob("/var/lib/serverdeck/sites/*.json")
	if err != nil {
		return nil, err
	}
	sites := make([]site, 0, len(paths))
	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		var value site
		if err := json.Unmarshal(data, &value); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		enabledPath := filepath.Join("/etc/nginx/sites-enabled", value.Domain)
		if value.WebServer == "apache" {
			enabledPath = filepath.Join("/etc/apache2/sites-enabled", value.Domain+".conf")
		}
		_, enabledErr := os.Lstat(enabledPath)
		value.Enabled = enabledErr == nil
		sites = append(sites, value)
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].Domain < sites[j].Domain })
	return sites, nil
}

func createSite(domain, kind string) (site, error) {
	value := site{}
	if os.Geteuid() != 0 {
		return value, errors.New("site-create must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if len(domain) > 253 || !domainPattern.MatchString(domain) {
		return value, errors.New("invalid domain name")
	}
	if kind != "static" && kind != "php" {
		return value, errors.New("site kind must be static or php")
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
	root := filepath.Join("/var/www", domain, "public")
	for _, path := range []string{configPath, enabledPath, metadataPath} {
		if _, err := os.Lstat(path); err == nil {
			return value, errors.New("a managed site with this domain already exists")
		}
	}

	phpVersion := ""
	phpBlock := ""
	if kind == "php" {
		sockets, _ := filepath.Glob("/run/php/php*-fpm.sock")
		if len(sockets) == 0 {
			return value, errors.New("no active PHP-FPM socket was found")
		}
		sort.Strings(sockets)
		socket := sockets[len(sockets)-1]
		phpVersion = strings.TrimSuffix(strings.TrimPrefix(filepath.Base(socket), "php"), "-fpm.sock")
		if webServer == "nginx" {
			phpBlock = fmt.Sprintf(`
    index index.php index.html;
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:%s;
    }
`, socket)
		} else {
			if output, err := exec.Command("a2enmod", "proxy_fcgi", "setenvif", "rewrite").CombinedOutput(); err != nil {
				return value, fmt.Errorf("enable Apache PHP modules: %s", tail(string(output), 800))
			}
			phpBlock = fmt.Sprintf("    <FilesMatch \"\\.php$\">\n        SetHandler \"proxy:unix:%s|fcgi://localhost/\"\n    </FilesMatch>\n", socket)
		}
	}

	config := ""
	if webServer == "nginx" {
		config = fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    root %s;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
%s}
`, domain, root, phpBlock)
	} else {
		config = fmt.Sprintf(`<VirtualHost *:80>
    ServerName %s
    DocumentRoot %s
    <Directory %s>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
        DirectoryIndex index.php index.html
    </Directory>
%s</VirtualHost>
`, domain, root, root, phpBlock)
	}

	if err := os.MkdirAll(root, 0755); err != nil {
		return value, fmt.Errorf("create document root: %w", err)
	}
	indexName := "index.html"
	indexBody := "<!doctype html><html><head><title>" + domain + "</title></head><body><h1>" + domain + "</h1><p>Managed by ServerDeck.</p></body></html>\n"
	if kind == "php" {
		indexName = "index.php"
		indexBody = "<?php echo '<h1>" + domain + "</h1><p>Managed by ServerDeck.</p>'; ?>\n"
	}
	if err := os.WriteFile(filepath.Join(root, indexName), []byte(indexBody), 0644); err != nil {
		return value, fmt.Errorf("create index: %w", err)
	}
	if err := atomicWrite(configPath, []byte(config), 0644); err != nil {
		return value, err
	}
	if webServer == "nginx" {
		if err := os.Symlink(configPath, enabledPath); err != nil {
			_ = os.Remove(configPath)
			return value, fmt.Errorf("enable site: %w", err)
		}
	} else if output, err := exec.Command("a2ensite", domain+".conf").CombinedOutput(); err != nil {
		_ = os.Remove(configPath)
		return value, fmt.Errorf("enable Apache site: %s", tail(string(output), 800))
	}
	validation := exec.Command("nginx", "-t")
	if webServer == "apache" {
		validation = exec.Command("apache2ctl", "configtest")
	}
	if output, err := validation.CombinedOutput(); err != nil {
		_ = os.Remove(enabledPath)
		_ = os.Remove(configPath)
		_ = writeAudit("site.create.failed", false, domain+": "+tail(string(output), 800))
		return value, fmt.Errorf("%s validation failed: %s", webServer, tail(string(output), 800))
	}

	value = site{Domain: domain, Kind: kind, Root: root, Enabled: true, PHPVersion: phpVersion, CreatedAt: time.Now().UTC().Format(time.RFC3339), WebServer: webServer}
	metadata, _ := json.MarshalIndent(value, "", "  ")
	if err := atomicWrite(metadataPath, append(metadata, '\n'), 0644); err != nil {
		_ = os.Remove(enabledPath)
		_ = os.Remove(configPath)
		return site{}, err
	}
	if output, err := exec.Command("systemctl", "reload", map[string]string{"nginx": "nginx", "apache": "apache2"}[webServer]).CombinedOutput(); err != nil {
		_ = os.Remove(metadataPath)
		_ = os.Remove(enabledPath)
		_ = os.Remove(configPath)
		return site{}, fmt.Errorf("reload nginx: %s", tail(string(output), 800))
	}
	_ = writeAudit("site.create.completed", true, domain+" ("+kind+")")
	return value, nil
}

func planWebMigration(target string) (webMigrationPlan, error) {
	plan := webMigrationPlan{Target: target, Sites: []string{}, TLS: []string{}, SafetyBackup: true, Allowed: true}
	if target != "nginx" && target != "apache" {
		return plan, errors.New("migration target must be nginx or apache")
	}
	sites, err := listSites()
	if err != nil { return plan, err }
	sources := map[string]bool{}
	for _, item := range sites {
		source := item.WebServer
		if source == "" { source = "nginx" }
		sources[source] = true
		plan.Sites = append(plan.Sites, item.Domain)
		if _, err := os.Stat(filepath.Join("/etc/letsencrypt/live", item.Domain, "cert.pem")); err == nil {
			plan.TLS = append(plan.TLS, item.Domain)
		}
	}
	if len(sites) == 0 {
		plan.Allowed = false
		plan.Reason = "No managed websites need migration"
		return plan, nil
	}
	if len(sources) != 1 {
		plan.Allowed = false
		plan.Reason = "Managed sites currently use mixed web servers; migrate them to one server before switching"
		return plan, nil
	}
	for source := range sources { plan.Source = source }
	if plan.Source == target {
		plan.Allowed = false
		plan.Reason = "Managed websites already use " + target
		return plan, nil
	}
	plan.Reason = fmt.Sprintf("Migrate %d managed website(s), including %d TLS site(s)", len(plan.Sites), len(plan.TLS))
	return plan, nil
}

func migrateWebServer(target string) (webMigrationPlan, error) {
	if os.Geteuid() != 0 { return webMigrationPlan{}, errors.New("web-migrate must run as root") }
	plan, err := planWebMigration(target)
	if err != nil { return plan, err }
	if !plan.Allowed { return plan, errors.New(plan.Reason) }
	safety, err := createBackup()
	if err != nil { return plan, fmt.Errorf("create migration safety backup: %w", err) }
	_ = writeAudit("web.migration.started", true, plan.Source+" -> "+target+" safety "+safety.ID)
	sourceUnit := map[string]string{"nginx": "nginx", "apache": "apache2"}[plan.Source]
	targetUnit := map[string]string{"nginx": "nginx", "apache": "apache2"}[target]
	created := []string{}
	metadataOriginals := map[string][]byte{}
	rollback := func(detail string) {
		_ = exec.Command("systemctl", "stop", targetUnit).Run()
		for _, path := range created { _ = os.Remove(path) }
		for path, contents := range metadataOriginals { _ = atomicWrite(path, contents, 0644) }
		_ = exec.Command("systemctl", "start", sourceUnit).Run()
		_ = writeAudit("web.migration.rolled-back", false, detail+" safety "+safety.ID)
	}
	if err := exec.Command("systemctl", "stop", sourceUnit).Run(); err != nil {
		return plan, fmt.Errorf("stop %s before migration: %w", plan.Source, err)
	}
	packages := []string{"nginx", "certbot", "python3-certbot-nginx"}
	if target == "apache" { packages = []string{"apache2", "certbot", "python3-certbot-apache"} }
	arguments := append([]string{"install", "-y", "--no-install-recommends"}, packages...)
	if output, installErr := exec.Command("apt-get", arguments...).CombinedOutput(); installErr != nil {
		rollback("install target: "+tail(string(output), 800))
		return plan, fmt.Errorf("install %s: %s", target, tail(string(output), 800))
	}
	if target == "apache" {
		if output, moduleErr := exec.Command("a2enmod", "proxy", "proxy_http", "proxy_fcgi", "setenvif", "rewrite", "headers", "ssl").CombinedOutput(); moduleErr != nil {
			rollback("enable Apache modules: "+tail(string(output), 800))
			return plan, fmt.Errorf("enable Apache modules: %s", tail(string(output), 800))
		}
	}
	sites, _ := listSites()
	for _, item := range sites {
		config, renderErr := renderSiteForWebServer(item, target)
		if renderErr != nil { rollback(renderErr.Error()); return plan, renderErr }
		configPath := filepath.Join("/etc/nginx/sites-available", item.Domain)
		enabledPath := filepath.Join("/etc/nginx/sites-enabled", item.Domain)
		if target == "apache" {
			configPath = filepath.Join("/etc/apache2/sites-available", item.Domain+".conf")
			enabledPath = filepath.Join("/etc/apache2/sites-enabled", item.Domain+".conf")
		}
		if _, statErr := os.Lstat(configPath); statErr == nil {
			rollback("target configuration already exists for "+item.Domain)
			return plan, errors.New("target configuration already exists for " + item.Domain)
		}
		if writeErr := atomicWrite(configPath, []byte(config), 0644); writeErr != nil { rollback(writeErr.Error()); return plan, writeErr }
		created = append(created, configPath)
		if symlinkErr := os.Symlink(configPath, enabledPath); symlinkErr != nil { rollback(symlinkErr.Error()); return plan, symlinkErr }
		created = append(created, enabledPath)
	}
	validation := exec.Command("nginx", "-t")
	if target == "apache" { validation = exec.Command("apache2ctl", "configtest") }
	if output, validationErr := validation.CombinedOutput(); validationErr != nil {
		rollback("validation: "+tail(string(output), 1000))
		return plan, fmt.Errorf("%s validation failed: %s", target, tail(string(output), 1000))
	}
	if output, startErr := exec.Command("systemctl", "enable", "--now", targetUnit).CombinedOutput(); startErr != nil {
		rollback("start target: "+tail(string(output), 800))
		return plan, fmt.Errorf("start %s: %s", target, tail(string(output), 800))
	}
	for _, item := range sites {
		item.WebServer = target
		metadataPath := filepath.Join("/var/lib/serverdeck/sites", item.Domain+".json")
		if original, readErr := os.ReadFile(metadataPath); readErr == nil { metadataOriginals[metadataPath] = original }
		encoded, _ := json.MarshalIndent(item, "", "  ")
		if metadataErr := atomicWrite(metadataPath, append(encoded, '\n'), 0644); metadataErr != nil {
			rollback(metadataErr.Error())
			return plan, metadataErr
		}
	}
	_ = writeAudit("web.migration.completed", true, plan.Source+" -> "+target+" safety "+safety.ID)
	return plan, nil
}

func renderSiteForWebServer(item site, target string) (string, error) {
	tls := false
	certificatePath := filepath.Join("/etc/letsencrypt/live", item.Domain)
	if _, err := os.Stat(filepath.Join(certificatePath, "cert.pem")); err == nil { tls = true }
	if target == "nginx" {
		listenTLS := ""
		if tls { listenTLS = fmt.Sprintf("    listen 443 ssl;\n    listen [::]:443 ssl;\n    ssl_certificate %s/fullchain.pem;\n    ssl_certificate_key %s/privkey.pem;\n", certificatePath, certificatePath) }
		if item.Kind == "node" {
			return fmt.Sprintf("server {\n    listen 80;\n    listen [::]:80;\n%s    server_name %s;\n    location / {\n        proxy_pass http://127.0.0.1:%d;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n}\n", listenTLS, item.Domain, item.Port), nil
		}
		phpBlock := ""
		if item.Kind == "php" {
			socket := "/run/php/php"+item.PHPVersion+"-fpm.sock"
			if _, err := os.Stat(socket); err != nil { return "", errors.New("PHP-FPM socket is unavailable for "+item.Domain) }
			phpBlock = fmt.Sprintf("    location ~ \\.php$ {\n        include snippets/fastcgi-php.conf;\n        fastcgi_pass unix:%s;\n    }\n", socket)
		}
		return fmt.Sprintf("server {\n    listen 80;\n    listen [::]:80;\n%s    server_name %s;\n    root %s;\n    index index.php index.html;\n    location / { try_files $uri $uri/ /index.html; }\n%s}\n", listenTLS, item.Domain, item.Root, phpBlock), nil
	}
	if target != "apache" { return "", errors.New("unsupported migration target") }
	body := ""
	if item.Kind == "node" {
		body = fmt.Sprintf("    ProxyPreserveHost On\n    ProxyPass / http://127.0.0.1:%d/\n    ProxyPassReverse / http://127.0.0.1:%d/\n    RequestHeader set X-Forwarded-Proto expr=%%{REQUEST_SCHEME}\n", item.Port, item.Port)
	} else {
		body = fmt.Sprintf("    DocumentRoot %s\n    <Directory %s>\n        Options FollowSymLinks\n        AllowOverride All\n        Require all granted\n        DirectoryIndex index.php index.html\n    </Directory>\n", item.Root, item.Root)
		if item.Kind == "php" {
			socket := "/run/php/php"+item.PHPVersion+"-fpm.sock"
			if _, err := os.Stat(socket); err != nil { return "", errors.New("PHP-FPM socket is unavailable for "+item.Domain) }
			body += fmt.Sprintf("    <FilesMatch \"\\.php$\">\n        SetHandler \"proxy:unix:%s|fcgi://localhost/\"\n    </FilesMatch>\n", socket)
		}
	}
	config := fmt.Sprintf("<VirtualHost *:80>\n    ServerName %s\n%s</VirtualHost>\n", item.Domain, body)
	if tls {
		config += fmt.Sprintf("<VirtualHost *:443>\n    ServerName %s\n    SSLEngine on\n    SSLCertificateFile %s/fullchain.pem\n    SSLCertificateKeyFile %s/privkey.pem\n%s</VirtualHost>\n", item.Domain, certificatePath, certificatePath, body)
	}
	return config, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".serverdeck-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func installWebStack(webServer, database string, php, node, redis, ftp, fail2ban, firewall bool, sshPort int) (map[string]interface{}, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("stack-install must run as root")
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		return nil, errors.New("apt-get is required")
	}

	webPackages := map[string][]string{
		"nginx": {"nginx", "certbot", "python3-certbot-nginx"},
		"apache": {"apache2", "certbot", "python3-certbot-apache"},
		"none": {},
	}
	databasePackages := map[string][]string{
		"mariadb": {"mariadb-server"},
		"mysql": {"mysql-server"},
		"postgresql": {"postgresql"},
		"none": {},
	}
	packages, validWeb := webPackages[webServer]
	databaseSelection, validDatabase := databasePackages[database]
	if !validWeb || !validDatabase {
		return nil, errors.New("unsupported hosting stack selection")
	}
	if sshPort < 1 || sshPort > 65535 {
		return nil, errors.New("SSH port must be between 1 and 65535")
	}
	if webServer == "nginx" && packageVersion("apache2") != "" {
		return nil, errors.New("Apache is already installed. Remove or migrate it before selecting Nginx")
	}
	if webServer == "apache" && packageVersion("nginx") != "" {
		return nil, errors.New("Nginx is already installed. Remove or migrate it before selecting Apache")
	}
	if database == "mariadb" && packageVersion("mysql-server") != "" {
		return nil, errors.New("MySQL is already installed. MariaDB cannot be installed beside it safely")
	}
	if database == "mysql" && packageVersion("mariadb-server") != "" {
		return nil, errors.New("MariaDB is already installed. MySQL cannot be installed beside it safely")
	}
	if database == "postgresql" && (packageVersion("mariadb-server") != "" || packageVersion("mysql-server") != "") {
		return nil, errors.New("A MySQL-compatible database is already installed. Choose one managed database engine per server")
	}
	if (database == "mariadb" || database == "mysql") && packageVersion("postgresql") != "" {
		return nil, errors.New("PostgreSQL is already installed. Choose one managed database engine per server")
	}
	packages = append(packages, databaseSelection...)
	if php {
		packages = append(packages, "php-fpm", "php-cli", "php-curl", "php-mbstring", "php-xml", "php-zip")
	}
	if php && (database == "mariadb" || database == "mysql") {
		packages = append(packages, "php-mysql")
	}
	if php && database == "postgresql" {
		packages = append(packages, "php-pgsql")
	}
	if node {
		packages = append(packages, "nodejs", "npm")
	}
	if redis {
		packages = append(packages, "redis-server")
	}
	if ftp {
		packages = append(packages, "vsftpd")
	}
	if fail2ban {
		packages = append(packages, "fail2ban")
	}
	if len(packages) == 0 {
		return map[string]interface{}{"installed": []string{}}, nil
	}

	if err := writeAudit("stack.install.started", true, fmt.Sprintf("web=%s database=%s php=%t node=%t redis=%t ftp=%t", webServer, database, php, node, redis, ftp)); err != nil {
		return nil, err
	}
	if output, err := exec.Command("apt-get", "update").CombinedOutput(); err != nil {
		_ = writeAudit("stack.install.failed", false, tail(string(output), 800))
		return nil, fmt.Errorf("apt-get update failed: %s", tail(string(output), 800))
	}
	arguments := append([]string{"install", "-y", "--no-install-recommends"}, packages...)
	if output, err := exec.Command("apt-get", arguments...).CombinedOutput(); err != nil {
		_ = writeAudit("stack.install.failed", false, tail(string(output), 800))
		return nil, fmt.Errorf("package installation failed: %s", tail(string(output), 800))
	}
	units := []string{}
	if webServer == "nginx" {
		units = append(units, "nginx")
	}
	if webServer == "apache" {
		units = append(units, "apache2")
	}
	if database == "mariadb" {
		units = append(units, "mariadb")
	}
	if database == "mysql" {
		units = append(units, "mysql")
	}
	if database == "postgresql" {
		units = append(units, "postgresql")
	}
	if redis {
		units = append(units, "redis-server")
	}
	if ftp {
		units = append(units, "vsftpd")
	}
	for _, name := range units {
		if output, err := exec.Command("systemctl", "enable", "--now", name).CombinedOutput(); err != nil {
			_ = writeAudit("stack.install.failed", false, tail(string(output), 800))
			return nil, fmt.Errorf("enable %s: %s", name, tail(string(output), 800))
		}
	}
	if fail2ban {
		configuration := "[sshd]\nenabled = true\nbackend = systemd\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n"
		if err := atomicWrite("/etc/fail2ban/jail.d/serverdeck.local", []byte(configuration), 0644); err != nil {
			return nil, err
		}
		if output, err := exec.Command("systemctl", "enable", "--now", "fail2ban").CombinedOutput(); err != nil {
			return nil, fmt.Errorf("enable Fail2ban: %s", tail(string(output), 800))
		}
	}
	if firewall {
		if _, err := enableFirewall(sshPort); err != nil {
			return nil, err
		}
	}
	if err := writeAudit("stack.install.completed", true, "web stack installation completed"); err != nil {
		return nil, err
	}
	return map[string]interface{}{"installed": packages, "web_server": webServer, "database": database, "fail2ban": fail2ban, "firewall": firewall}, nil
}

func writeAudit(action string, success bool, detail string) error {
	directory := "/var/log/serverdeck"
	if err := os.MkdirAll(directory, 0750); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	path := filepath.Join(directory, "audit.jsonl")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()
	record := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"action":    action,
		"success":   success,
		"detail":    detail,
		"uid":       os.Getuid(),
	}
	return json.NewEncoder(file).Encode(record)
}

func tail(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[len(value)-limit:]
}

func inspectServices() ([]service, error) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, errors.New("systemd is not available")
	}
	names := make([]string, 0, len(managedServices))
	for name := range managedServices {
		names = append(names, name)
	}
	sort.Strings(names)

	services := make([]service, 0, len(names))
	for _, name := range names {
		loadState := systemctl("show", name+".service", "--property=LoadState", "--value")
		activeState := systemctl("is-active", name+".service")
		active := strings.TrimSpace(activeState) == "active"
		if name == "ufw" {
			active = firewallIsActive()
		}
		services = append(services, service{
			Name:        name,
			Installed:   strings.TrimSpace(loadState) == "loaded",
			Active:      active,
			Description: managedServices[name],
		})
	}
	phpUnits, _ := exec.Command("systemctl", "list-unit-files", "php*-fpm.service", "--no-legend", "--no-pager").Output()
	for _, line := range strings.Split(string(phpUnits), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".service")
		services = append(services, service{
			Name:        name,
			Installed:   true,
			Active:      strings.TrimSpace(systemctl("is-active", fields[0])) == "active",
			Description: "PHP application runtime",
		})
	}
	sites, _ := listSites()
	for _, site := range sites {
		if site.Service == "" {
			continue
		}
		services = append(services, service{Name: site.Service, Installed: true, Active: strings.TrimSpace(systemctl("is-active", site.Service+".service")) == "active", Description: "Node.js project for " + site.Domain})
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	return services, nil
}

func systemctl(arguments ...string) string {
	output, _ := exec.Command("systemctl", arguments...).Output()
	return string(output)
}
