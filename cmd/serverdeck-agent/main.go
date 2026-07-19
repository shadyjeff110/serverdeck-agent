package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	version         = "0.42.0"
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
	SubState    string `json:"sub_state,omitempty"`
	PID         int    `json:"pid,omitempty"`
	Memory      int64  `json:"memory,omitempty"`
	Uptime      string `json:"uptime,omitempty"`
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
	// Set when a database was created alongside the site, so the association
	// exists for sites that are not one of the packaged applications.
	Database     string `json:"database,omitempty"`
	DatabaseUser string `json:"database_user,omitempty"`
	// Present only in the response that creates it, never in the stored record.
	DatabasePassword string `json:"database_password,omitempty"`
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
	ID       string `json:"id"`
	File     string `json:"file"`
	URI      string `json:"uri"`
	Suite    string `json:"suite,omitempty"`
	Official bool   `json:"official"`
	SignedBy string `json:"signed_by,omitempty"`
	Enabled  bool   `json:"enabled"`
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
	Support    string   `json:"support"`
}

type mailAliasInfo struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type mailDomainInfo struct {
	Domain    string          `json:"domain"`
	DKIMReady bool            `json:"dkim_ready"`
	Accounts  []string        `json:"accounts"`
	Aliases   []mailAliasInfo `json:"aliases"`
}

type mailStatus struct {
	Hostname         string           `json:"hostname"`
	PostfixInstalled bool             `json:"postfix_installed"`
	PostfixActive    bool             `json:"postfix_active"`
	DovecotInstalled bool             `json:"dovecot_installed"`
	DovecotActive    bool             `json:"dovecot_active"`
	Mailname         string           `json:"mailname,omitempty"`
	ReadyForSetup    bool             `json:"ready_for_setup"`
	Domains          []mailDomainInfo `json:"domains"`
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
	Mode      string `json:"mode"`
	Perm      string `json:"perm"`
	Owner     string `json:"owner"`
	Group     string `json:"group"`
}

type fileContents struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type trashEntry struct {
	TrashName    string `json:"trash_name"`
	OriginalPath string `json:"original_path"`
	DeletedAt    string `json:"deleted_at"`
	Directory    bool   `json:"directory"`
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
	"nginx":        "Web server",
	"apache2":      "Web server",
	"mariadb":      "MariaDB database",
	"mysql":        "MySQL database",
	"postgresql":   "PostgreSQL database",
	"postfix":      "Mail transport",
	"dovecot":      "Mail delivery",
	"docker":       "Container runtime",
	"redis-server": "Cache and data store",
	"vsftpd":       "Legacy FTP server",
	"fail2ban":     "Intrusion prevention",
	"ufw":          "Firewall",
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
	case "cron-list":
		data, err = listCronJobs()
	case "cron-add":
		if len(os.Args) != 5 {
			err = errors.New("cron-add requires an encoded schedule, user, and command")
			break
		}
		var addSchedule, addUsername, addCommand string
		addSchedule, err = decodeArgument(os.Args[2])
		if err == nil {
			addUsername, err = decodeArgument(os.Args[3])
		}
		if err == nil {
			addCommand, err = decodeArgument(os.Args[4])
		}
		if err == nil {
			data, err = addCronJob(addSchedule, addUsername, addCommand)
		}
	case "cron-update":
		if len(os.Args) != 6 {
			err = errors.New("cron-update requires an encoded ID, schedule, user, and command")
			break
		}
		var updateID, updateSchedule, updateUsername, updateCommand string
		updateID, err = decodeArgument(os.Args[2])
		if err == nil {
			updateSchedule, err = decodeArgument(os.Args[3])
		}
		if err == nil {
			updateUsername, err = decodeArgument(os.Args[4])
		}
		if err == nil {
			updateCommand, err = decodeArgument(os.Args[5])
		}
		if err == nil {
			data, err = updateCronJob(updateID, updateSchedule, updateUsername, updateCommand)
		}
	case "cron-delete":
		if len(os.Args) != 3 {
			err = errors.New("cron-delete requires an encoded job ID")
			break
		}
		id, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = deleteCronJob(id)
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
		if err == nil {
			node, err = strconv.ParseBool(os.Args[5])
		}
		if err == nil {
			redis, err = strconv.ParseBool(os.Args[6])
		}
		if err == nil {
			ftp, err = strconv.ParseBool(os.Args[7])
		}
		if err == nil {
			fail2ban, err = strconv.ParseBool(os.Args[8])
		}
		if err == nil {
			firewall, err = strconv.ParseBool(os.Args[9])
		}
		if err == nil {
			sshPort, err = strconv.Atoi(os.Args[10])
		}
		if err == nil {
			data, err = installWebStack(os.Args[2], os.Args[3], php, node, redis, ftp, fail2ban, firewall, sshPort)
		}
	case "site-list":
		data, err = listSites()
	case "site-create":
		if len(os.Args) != 6 {
			err = errors.New("site-create requires a domain, kind, canonical host, and database flag")
			break
		}
		var decoded []byte
		decoded, err = base64.RawURLEncoding.DecodeString(os.Args[2])
		if err == nil {
			data, err = createSiteWithDatabase(string(decoded), os.Args[3],
				parseCanonicalHost(os.Args[4]), os.Args[5] == "true")
		}
	case "app-catalog":
		data, err = appCatalog()
	case "app-list":
		data, err = listInstalledApps()
	case "app-install":
		if len(os.Args) != 5 {
			err = errors.New("app-install requires an app ID, encoded domain, and database choice")
			break
		}
		appDomain, decodeErr := decodeArgument(os.Args[3])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		createDB, parseErr := strconv.ParseBool(os.Args[4])
		if parseErr != nil {
			err = parseErr
			break
		}
		data, err = installApp(os.Args[2], appDomain, createDB)
	case "runtime-list":
		data, err = listRuntimes()
	case "software-list":
		data, err = listSoftware()
	case "software-config-read":
		if len(os.Args) != 3 {
			err = errors.New("software-config-read requires an encoded configuration ID")
			break
		}
		configID, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = readSoftwareConfig(configID)
	case "software-config-write":
		if len(os.Args) != 4 {
			err = errors.New("software-config-write requires an encoded configuration ID and encoded content")
			break
		}
		configID, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = writeSoftwareConfig(configID, os.Args[3])
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
	case "source-disable":
		if len(os.Args) != 3 {
			err = errors.New("source-disable requires an encoded catalog ID")
			break
		}
		sourceID, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = disablePackageSource(sourceID)
	case "source-add-ppa":
		if len(os.Args) != 3 {
			err = errors.New("source-add-ppa requires an encoded PPA reference")
			break
		}
		reference, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = addPPA(reference)
	case "source-remove-ppa":
		if len(os.Args) != 3 {
			err = errors.New("source-remove-ppa requires an encoded PPA reference")
			break
		}
		reference, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = removePPA(reference)
	// The only command permitted to touch apt's cache. Everything else reads
	// what this leaves behind; see updatecheck.go.
	case "site-clone-plan":
		if len(os.Args) != 4 {
			err = errors.New("site-clone-plan requires encoded source and target domains")
			break
		}
		sourceDomain, sourceErr := decodeArgument(os.Args[2])
		targetDomain, targetErr := decodeArgument(os.Args[3])
		if sourceErr != nil || targetErr != nil {
			err = errors.New("could not decode the domains")
			break
		}
		data, err = planClone(strings.ToLower(sourceDomain), strings.ToLower(targetDomain))
	case "site-clone":
		if len(os.Args) != 4 {
			err = errors.New("site-clone requires encoded source and target domains")
			break
		}
		sourceDomain, sourceErr := decodeArgument(os.Args[2])
		targetDomain, targetErr := decodeArgument(os.Args[3])
		if sourceErr != nil || targetErr != nil {
			err = errors.New("could not decode the domains")
			break
		}
		data, err = cloneSite(strings.ToLower(sourceDomain), strings.ToLower(targetDomain))
	case "server-identity":
		data, err = readServerIdentity()
	case "server-hostname-set":
		if len(os.Args) != 3 {
			err = errors.New("server-hostname-set requires an encoded host name")
			break
		}
		hostname, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = setHostname(hostname)
	case "server-timezone-set":
		if len(os.Args) != 3 {
			err = errors.New("server-timezone-set requires an encoded time zone")
			break
		}
		zone, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = setTimezone(zone)
	case "server-timezone-list":
		data, err = listTimezones()
	// Unified backups. See backupv2.go for why site and server share a format.
	case "backup-create-v2":
		data, err = createServerBackup()
	case "backup-create-site":
		if len(os.Args) != 5 {
			err = errors.New("backup-create-site requires a domain and two content flags")
			break
		}
		backupDomain, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = createSiteBackup(backupDomain, os.Args[3] == "true", os.Args[4] == "true")
	case "disk-report":
		data, err = reportDisk()
	case "maintenance-sweep":
		data, err = sweepStaleWork()
	case "maintenance-timer-install":
		err = installMaintenanceTimer()
	case "backup-list-v2":
		data, err = listAllBackups()
	case "backup-delete":
		if len(os.Args) != 3 {
			err = errors.New("backup-delete requires an encoded backup id")
			break
		}
		backupIdentifier, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = deleteBackup(backupIdentifier)
	case "backup-restore-v2":
		if len(os.Args) != 3 {
			err = errors.New("backup-restore-v2 requires an encoded backup id")
			break
		}
		backupIdentifier, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = restoreBackupV2(backupIdentifier)
	case "backup-restore-site":
		if len(os.Args) != 5 {
			err = errors.New("backup-restore-site requires a backup id, source domain, and target domain")
			break
		}
		backupIdentifier, idErr := decodeArgument(os.Args[2])
		sourceDomain, sourceErr := decodeArgument(os.Args[3])
		restoreTarget, targetErr := decodeArgument(os.Args[4])
		if idErr != nil || sourceErr != nil || targetErr != nil {
			err = errors.New("could not decode the restore arguments")
			break
		}
		data, err = restoreSiteFromBackup(backupIdentifier, sourceDomain, restoreTarget)
	// Streams any backup archive to stdout for download.
	case "backup-download":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "backup-download requires an encoded backup id")
			os.Exit(2)
		}
		backupIdentifier, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			fmt.Fprintln(os.Stderr, "invalid backup id")
			os.Exit(2)
		}
		manifest, manifestErr := readBackupManifest(backupIdentifier)
		if manifestErr != nil {
			fmt.Fprintln(os.Stderr, manifestErr)
			os.Exit(1)
		}
		file, openErr := os.Open(manifest.Archive)
		if openErr != nil {
			fmt.Fprintln(os.Stderr, openErr)
			os.Exit(1)
		}
		defer file.Close()
		if _, copyErr := io.Copy(os.Stdout, file); copyErr != nil {
			fmt.Fprintln(os.Stderr, copyErr)
			os.Exit(1)
		}
		return
	case "site-export":
		if len(os.Args) != 3 {
			err = errors.New("site-export requires an encoded domain")
			break
		}
		exportDomain, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = exportSite(exportDomain)
	case "site-export-list":
		data, err = listSiteExports()
	case "site-export-delete":
		if len(os.Args) != 3 {
			err = errors.New("site-export-delete requires an encoded export id")
			break
		}
		exportID, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		err = deleteSiteExport(exportID)
	// Streams the archive to stdout for the app to save; deliberately not
	// wrapped in the JSON envelope, like backup-export.
	case "site-export-download":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "site-export-download requires an encoded export id")
			os.Exit(2)
		}
		exportID, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil || exportID == "" || strings.ContainsAny(exportID, "/\\") || strings.Contains(exportID, "..") {
			fmt.Fprintln(os.Stderr, "invalid export id")
			os.Exit(2)
		}
		file, openErr := os.Open(filepath.Join(siteExportDir, exportID+siteExportSuffix))
		if openErr != nil {
			fmt.Fprintln(os.Stderr, openErr)
			os.Exit(1)
		}
		defer file.Close()
		if _, copyErr := io.Copy(os.Stdout, file); copyErr != nil {
			fmt.Fprintln(os.Stderr, copyErr)
			os.Exit(1)
		}
		return
	case "site-import-plan":
		if len(os.Args) != 4 {
			err = errors.New("site-import-plan requires a session and encoded domain")
			break
		}
		importTarget, decodeErr := decodeArgument(os.Args[3])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = planSiteImport(os.Args[2], importTarget)
	case "site-import":
		if len(os.Args) != 4 {
			err = errors.New("site-import requires a session and encoded domain")
			break
		}
		importTarget, decodeErr := decodeArgument(os.Args[3])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = importSite(os.Args[2], importTarget)
	case "staging-list":
		data, err = listStaging()
	case "staging-refresh":
		if len(os.Args) != 3 {
			err = errors.New("staging-refresh requires an encoded domain")
			break
		}
		stagingDomain, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = refreshStaging(strings.ToLower(stagingDomain))
	case "software-check-updates":
		data, err = checkForUpdates(true)
	case "software-update-status":
		data = updateStatus()
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
	case "mail-domain-create":
		if len(os.Args) != 3 {
			err = errors.New("mail-domain-create requires an encoded domain")
			break
		}
		domain, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		err = createMailDomain(domain)
	case "mail-domain-delete":
		if len(os.Args) != 3 {
			err = errors.New("mail-domain-delete requires an encoded domain")
			break
		}
		domain, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		err = deleteMailDomain(domain)
	case "mail-account-create":
		if len(os.Args) != 4 {
			err = errors.New("mail-account-create requires encoded email and password")
			break
		}
		email, emailErr := decodeArgument(os.Args[2])
		password, passErr := decodeArgument(os.Args[3])
		if emailErr != nil {
			err = emailErr
			break
		}
		if passErr != nil {
			err = passErr
			break
		}
		err = createMailAccount(email, password)
	case "mail-account-delete":
		if len(os.Args) != 3 {
			err = errors.New("mail-account-delete requires an encoded email")
			break
		}
		email, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		err = deleteMailAccount(email)
	case "mail-alias-create":
		if len(os.Args) != 4 {
			err = errors.New("mail-alias-create requires encoded source and destination")
			break
		}
		source, srcErr := decodeArgument(os.Args[2])
		dest, destErr := decodeArgument(os.Args[3])
		if srcErr != nil {
			err = srcErr
			break
		}
		if destErr != nil {
			err = destErr
			break
		}
		err = createMailAlias(source, dest)
	case "mail-alias-delete":
		if len(os.Args) != 3 {
			err = errors.New("mail-alias-delete requires an encoded source address")
			break
		}
		source, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		err = deleteMailAlias(source)
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
		if len(os.Args) != 5 {
			err = errors.New("file-delete requires an encoded domain, path, and permanent flag")
			break
		}
		data, err = deleteManagedFileEncoded(os.Args[2], os.Args[3], os.Args[4])
	case "file-trash-list":
		if len(os.Args) != 3 {
			err = errors.New("file-trash-list requires an encoded domain")
			break
		}
		data, err = listTrashedFilesEncoded(os.Args[2])
	case "file-trash-restore":
		if len(os.Args) != 4 {
			err = errors.New("file-trash-restore requires an encoded domain and trash name")
			break
		}
		data, err = restoreTrashedFileEncoded(os.Args[2], os.Args[3])
	case "file-trash-empty":
		if len(os.Args) != 3 {
			err = errors.New("file-trash-empty requires an encoded domain")
			break
		}
		data, err = emptyTrashEncoded(os.Args[2])
	case "file-create-dir":
		if len(os.Args) != 4 {
			err = errors.New("file-create-dir requires an encoded domain and path")
			break
		}
		data, err = createManagedDirEncoded(os.Args[2], os.Args[3])
	case "file-create-file":
		if len(os.Args) != 4 {
			err = errors.New("file-create-file requires an encoded domain and path")
			break
		}
		data, err = createManagedFileEncoded(os.Args[2], os.Args[3])
	case "file-chmod":
		if len(os.Args) != 5 {
			err = errors.New("file-chmod requires an encoded domain, path, and encoded mode")
			break
		}
		data, err = chmodManagedFileEncoded(os.Args[2], os.Args[3], os.Args[4])
	case "file-chown":
		if len(os.Args) != 6 {
			err = errors.New("file-chown requires an encoded domain, path, encoded owner, and encoded group")
			break
		}
		data, err = chownManagedFileEncoded(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
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
	case "image-list":
		data, err = listImages()
	case "image-pull":
		if len(os.Args) != 3 {
			err = errors.New("image-pull requires an encoded image reference")
			break
		}
		ref, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = pullImage(ref)
	case "image-remove":
		if len(os.Args) != 3 {
			err = errors.New("image-remove requires an encoded image reference")
			break
		}
		ref, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = removeImage(ref)
	case "container-create":
		if len(os.Args) != 3 {
			err = errors.New("container-create requires an encoded spec")
			break
		}
		spec, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = createContainer(spec)
	case "container-remove":
		if len(os.Args) != 3 {
			err = errors.New("container-remove requires an encoded container name")
			break
		}
		name, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = removeContainer(name)
	case "container-publish":
		if len(os.Args) != 4 {
			err = errors.New("container-publish requires an encoded domain and host port")
			break
		}
		domain, domainErr := decodeArgument(os.Args[2])
		portValue, portErr := decodeArgument(os.Args[3])
		if domainErr != nil {
			err = domainErr
			break
		}
		if portErr != nil {
			err = portErr
			break
		}
		port, parseErr := parsePort(portValue)
		if parseErr != nil {
			err = parseErr
			break
		}
		data, err = publishContainer(domain, port)
	case "docker-catalog":
		data = dockerCatalog()
	case "docker-app-install":
		if len(os.Args) != 4 {
			err = errors.New("docker-app-install requires an encoded app id and options")
			break
		}
		appID, idErr := decodeArgument(os.Args[2])
		options, optionsErr := decodeArgument(os.Args[3])
		if idErr != nil {
			err = idErr
			break
		}
		if optionsErr != nil {
			err = optionsErr
			break
		}
		data, err = installDockerApp(appID, options)
	case "compose-list":
		data, err = listComposeProjects()
	case "compose-up":
		if len(os.Args) != 4 {
			err = errors.New("compose-up requires an encoded project name and file")
			break
		}
		name, nameErr := decodeArgument(os.Args[2])
		content, contentErr := decodeArgument(os.Args[3])
		if nameErr != nil {
			err = nameErr
			break
		}
		if contentErr != nil {
			err = contentErr
			break
		}
		data, err = composeUp(name, content)
	case "compose-down":
		if len(os.Args) != 3 {
			err = errors.New("compose-down requires an encoded project name")
			break
		}
		name, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = composeDown(name)
	case "wp-list":
		data, err = listWordPressSites()
	case "wp-settings-get":
		if len(os.Args) != 3 {
			err = errors.New("wp-settings-get requires an encoded domain")
			break
		}
		domain, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = getWordPressSite(domain)
	case "wp-settings-set":
		if len(os.Args) != 4 {
			err = errors.New("wp-settings-set requires an encoded domain and settings")
			break
		}
		domain, domainErr := decodeArgument(os.Args[2])
		settings, settingsErr := decodeArgument(os.Args[3])
		if domainErr != nil {
			err = domainErr
			break
		}
		if settingsErr != nil {
			err = settingsErr
			break
		}
		data, err = updateWordPressSettings(domain, settings)
	case "wp-user-password":
		if len(os.Args) != 5 {
			err = errors.New("wp-user-password requires an encoded domain, login, and password")
			break
		}
		domain, domainErr := decodeArgument(os.Args[2])
		login, loginErr := decodeArgument(os.Args[3])
		password, passwordErr := decodeArgument(os.Args[4])
		if domainErr != nil {
			err = domainErr
			break
		}
		if loginErr != nil {
			err = loginErr
			break
		}
		if passwordErr != nil {
			err = passwordErr
			break
		}
		if resetErr := resetWordPressPassword(domain, login, password); resetErr != nil {
			err = resetErr
			break
		}
		data = map[string]bool{"reset": true}
	case "wp-core-update":
		if len(os.Args) != 3 {
			err = errors.New("wp-core-update requires an encoded domain")
			break
		}
		domain, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = updateWordPressCore(domain)
	case "system-reboot":
		data, err = rebootServer()
	case "wp-import":
		if len(os.Args) != 4 {
			err = errors.New("wp-import requires an encoded domain and session")
			break
		}
		domain, domainErr := decodeArgument(os.Args[2])
		session, sessionErr := decodeArgument(os.Args[3])
		if domainErr != nil {
			err = domainErr
			break
		}
		if sessionErr != nil {
			err = sessionErr
			break
		}
		data, err = importWPress(domain, session)
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
	case "site-delete":
		if len(os.Args) != 4 {
			err = errors.New("site-delete requires an encoded domain and delete-root flag")
			break
		}
		decoded, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		deleteRoot, parseErr := strconv.ParseBool(os.Args[3])
		if parseErr != nil {
			err = parseErr
			break
		}
		err = deleteSite(decoded, deleteRoot)
	case "site-update":
		if len(os.Args) != 5 {
			err = errors.New("site-update requires an encoded domain, encoded new root, and encoded PHP version")
			break
		}
		domain, domainErr := decodeArgument(os.Args[2])
		if domainErr != nil {
			err = domainErr
			break
		}
		newRoot, rootErr := decodeArgument(os.Args[3])
		if rootErr != nil {
			err = rootErr
			break
		}
		phpVersion, phpErr := decodeArgument(os.Args[4])
		if phpErr != nil {
			err = phpErr
			break
		}
		err = updateSite(domain, newRoot, phpVersion)
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
	case "database-delete":
		if len(os.Args) != 3 {
			err = errors.New("database-delete requires an encoded database name")
			break
		}
		name, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		err = deleteDatabase(name)
	case "tls-list":
		data, err = listTLS()
	case "tls-issue":
		if len(os.Args) != 4 && len(os.Args) != 5 {
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
		data, err = issueTLS(string(domain), string(email), len(os.Args) == 5 && os.Args[4] == "force")
	case "tls-detail":
		if len(os.Args) != 3 {
			err = errors.New("tls-detail requires an encoded domain")
			break
		}
		domain, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = detailTLS(domain)
	case "tls-remove":
		if len(os.Args) != 3 {
			err = errors.New("tls-remove requires an encoded domain")
			break
		}
		domain, decodeErr := decodeArgument(os.Args[2])
		if decodeErr != nil {
			err = decodeErr
			break
		}
		data, err = removeTLS(domain)
	case "tls-dns-issue":
		if len(os.Args) != 5 && len(os.Args) != 6 {
			err = errors.New("tls-dns-issue requires an encoded domain, encoded email, and session")
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
		data, err = issueTLSDNS(string(domain), string(email), os.Args[4], len(os.Args) == 6 && os.Args[5] == "force")
	case "tls-dns-auth":
		if len(os.Args) != 3 {
			err = errors.New("tls-dns-auth requires a session")
			break
		}
		data, err = waitForDNSChallenge(os.Args[2])
	case "tls-dns-cleanup":
		data = map[string]bool{"cleaned": true}
	case "tls-dns-continue":
		if len(os.Args) != 3 {
			err = errors.New("tls-dns-continue requires a session")
			break
		}
		data, err = continueDNSChallenge(os.Args[2], false)
	case "tls-dns-abort":
		if len(os.Args) != 3 {
			err = errors.New("tls-dns-abort requires a session")
			break
		}
		data, err = continueDNSChallenge(os.Args[2], true)
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
	var failures []string
	for _, network := range []string{"tcp4", "tcp6"} {
		address, err := detectPublicAddressForNetwork(network)
		if err == nil {
			family := "IPv6"
			if network == "tcp4" {
				family = "IPv4"
			}
			return map[string]string{"address": address, "source": "Cloudflare " + family}, nil
		}
		failures = append(failures, err.Error())
	}
	return nil, fmt.Errorf("detect public address: %s", strings.Join(failures, "; "))
}

func detectPublicAddressForNetwork(network string) (string, error) {
	if network != "tcp4" && network != "tcp6" {
		return "", errors.New("unsupported address family")
	}
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport}
	request, err := http.NewRequest(http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "ServerDeck-Agent/"+version)
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("%s request: %w", network, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s request: HTTP %d", network, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if err != nil {
		return "", fmt.Errorf("read %s response: %w", network, err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "ip=") {
			address := strings.TrimSpace(strings.TrimPrefix(line, "ip="))
			parsed := net.ParseIP(address)
			if parsed == nil || (network == "tcp4" && parsed.To4() == nil) || (network == "tcp6" && parsed.To4() != nil) {
				return "", fmt.Errorf("public address service returned an invalid %s address", network)
			}
			return address, nil
		}
	}
	return "", fmt.Errorf("public %s address was not present in the detection response", network)
}

// upgradablePattern matches one line of `apt list --upgradable`.
var upgradablePattern = regexp.MustCompile(`^([^/]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: ([^]]+)\]`)

// listSystemUpdates runs on every refresh, so it only ever reads the cache.
//
// Falling back to apt when the cache is cold would reintroduce the ~77 MB spike
// this whole split exists to remove. An empty result means "not checked yet",
// which the Updates tab renders as a prompt rather than as "no updates".
func listSystemUpdates() ([]updatePackage, error) {
	packages, ok := cachedUpgradableReadOnly()
	if !ok {
		return []updatePackage{}, nil
	}
	return packages, nil
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
	// The package list and the upgrade both change what is upgradable.
	defer invalidateUpdateCache()

	command, cancelRefresh := commandContext(longTimeout, "apt-get", append(aptLockArgs, "update")...)
	defer cancelRefresh()
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	if output, err := command.CombinedOutput(); err != nil {
		_ = writeAudit("system.update.failed", false, tail(string(output), 800))
		return result, fmt.Errorf("refresh packages: %s", tail(string(output), 800))
	}

	command, cancelUpgrade := commandContext(longTimeout, "apt-get", append(aptLockArgs, "upgrade", "-y")...)
	defer cancelUpgrade()
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
	output, _ := run("ufw", "status")
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
	_, _ = run("systemctl", "stop", "serverdeck-firewall-rollback.timer")
	_, _ = run("systemctl", "reset-failed", "serverdeck-firewall-rollback.service")
	if output, err := run("systemd-run", "--unit=serverdeck-firewall-rollback", "--on-active=2m", "/usr/sbin/ufw", "--force", "disable"); err != nil {
		return securityStatus{}, fmt.Errorf("schedule firewall rollback: %s", tail(string(output), 800))
	}
	rules := [][]string{{"allow", fmt.Sprintf("%d/tcp", sshPort), "comment", "ServerDeck SSH"}, {"allow", "80/tcp", "comment", "ServerDeck HTTP"}, {"allow", "443/tcp", "comment", "ServerDeck HTTPS"}}
	for _, arguments := range rules {
		if output, err := run("ufw", arguments...); err != nil {
			return securityStatus{}, fmt.Errorf("add firewall rule: %s", tail(string(output), 800))
		}
	}
	if output, err := run("ufw", "--force", "enable"); err != nil {
		return securityStatus{}, fmt.Errorf("enable firewall: %s", tail(string(output), 800))
	}
	_ = writeAudit("firewall.enable.pending", true, fmt.Sprintf("SSH %d; rollback in 2 minutes", sshPort))
	return inspectSecurity()
}

func confirmFirewall() (securityStatus, error) {
	if os.Geteuid() != 0 {
		return securityStatus{}, errors.New("firewall-confirm must run as root")
	}
	_, _ = run("systemctl", "stop", "serverdeck-firewall-rollback.timer")
	_, _ = run("systemctl", "stop", "serverdeck-firewall-rollback.service")
	_ = writeAudit("firewall.enable.confirmed", true, "fresh SSH connection verified")
	return inspectSecurity()
}

func disableFirewall() (securityStatus, error) {
	if os.Geteuid() != 0 {
		return securityStatus{}, errors.New("firewall-disable must run as root")
	}
	_, _ = run("systemctl", "stop", "serverdeck-firewall-rollback.timer")
	if output, err := run("ufw", "--force", "disable"); err != nil {
		return securityStatus{}, fmt.Errorf("disable firewall: %s", tail(string(output), 800))
	}
	_ = writeAudit("firewall.disabled", true, "UFW disabled")
	return inspectSecurity()
}

func inspectSecurity() (securityStatus, error) {
	value := securityStatus{FirewallRules: []string{}, Findings: []string{}}
	ufwOutput, _ := run("ufw", "status")
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
	sshdOutput, _ := run("sshd", "-T")
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
	// Shares the cached apt result rather than re-running the query.
	value.UpdatesAvailable = cachedUpgradableCount()
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
	if output, err := runLong("apt-get", "-o", "DPkg::Lock::Timeout=30", "install", "-y", "--no-install-recommends", "fail2ban"); err != nil {
		return securityStatus{}, fmt.Errorf("install Fail2ban: %s", tail(string(output), 800))
	}
	configuration := "[sshd]\nenabled = true\nbackend = systemd\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n"
	if err := atomicWrite("/etc/fail2ban/jail.d/serverdeck.local", []byte(configuration), 0644); err != nil {
		return securityStatus{}, err
	}
	if output, err := run("systemctl", "enable", "--now", "fail2ban"); err != nil {
		return securityStatus{}, fmt.Errorf("enable Fail2ban: %s", tail(string(output), 800))
	}
	if err := mustRun("systemctl", "restart", "fail2ban"); err != nil {
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
	output, err := run("journalctl", "--unit", name+".service", "--no-pager", "--lines", strconv.Itoa(lines), "--output", "short-iso")
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
	output, err := run("systemctl", action, name+".service")
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
	failed, _ := runOutputWithTimeout(defaultTimeout, "systemctl", "--failed", "--no-legend", "--plain", "--no-pager")
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
	_, _ = run("systemctl", "daemon-reload")
	if output, err := run("systemctl", "enable", "--now", "serverdeck-backup.timer"); err != nil {
		return backupPolicy{}, fmt.Errorf("enable backup timer: %s", tail(string(output), 800))
	}
	_ = writeAudit("backup.policy.updated", true, fmt.Sprintf("daily %02d:00 retain %d", hour, retention))
	return value, nil
}

func runScheduledBackup() (map[string]interface{}, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("backup-run must run as root")
	}
	// The unified format, so a scheduled backup is the same thing as one made by
	// hand and appears in the same list.
	created, err := createServerBackup()
	if err != nil {
		return nil, err
	}
	policy, err := getBackupPolicy()
	if err != nil {
		return nil, err
	}
	removed, err := pruneBackupsToRetention(policy.Retention)
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
	if output, err := runLong("tar", "-xzf", value.Archive, "-C", staging); err != nil {
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
			_, _ = run("cp", "-a", filepath.Join("/etc", serverName, directory), serverSafety)
		}
	}
	rollbackWebConfig := func() {
		for _, serverName := range []string{"nginx", "apache2"} {
			for _, directory := range []string{"sites-available", "sites-enabled"} {
				saved := filepath.Join(configSafety, serverName, directory)
				if _, err := os.Stat(saved); err == nil {
					_ = os.RemoveAll(filepath.Join("/etc", serverName, directory))
					_, _ = run("cp", "-a", saved, filepath.Join("/etc", serverName)+"/")
				}
			}
		}
		if packageVersion("nginx") != "" {
			_, _ = run("systemctl", "reload", "nginx")
		}
		if packageVersion("apache2") != "" {
			_, _ = run("systemctl", "reload", "apache2")
		}
	}
	for _, serverName := range []string{"nginx", "apache2"} {
		for _, directory := range []string{"sites-available", "sites-enabled"} {
			source := filepath.Join(staging, "etc", serverName, directory)
			if _, err := os.Stat(source); err == nil {
				if output, err := run("cp", "-a", source+"/.", filepath.Join("/etc", serverName, directory)); err != nil {
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
				if output, err := run("cp", "-a", pair[0], pair[1]); err != nil {
					rollbackWebConfig()
					return result, fmt.Errorf("restore site %s: %s", domain, tail(string(output), 800))
				}
			}
		}
	}
	if packageVersion("nginx") != "" {
		if output, err := run("nginx", "-t"); err != nil {
			rollbackWebConfig()
			return result, fmt.Errorf("restored Nginx validation failed: %s", tail(string(output), 800))
		}
		if err := mustRun("systemctl", "reload", "nginx"); err != nil {
			rollbackWebConfig()
			return result, err
		}
	}
	if packageVersion("apache2") != "" {
		if output, err := run("apache2ctl", "configtest"); err != nil {
			rollbackWebConfig()
			return result, fmt.Errorf("restored Apache validation failed: %s", tail(string(output), 800))
		}
		if err := mustRun("systemctl", "reload", "apache2"); err != nil {
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
		command, cancelCommand := commandContext(longTimeout, "mariadb", name)
		defer cancelCommand()
		if engine == "MySQL" {
			command2, cancelCommand2 := commandContext(longTimeout, "mysql", name)
			command = command2
			defer cancelCommand2()
		} else if engine == "PostgreSQL" {
			command2, cancelCommand3 := commandContext(longTimeout, "runuser", "-u", "postgres", "--", "psql", "--set", "ON_ERROR_STOP=1", "--dbname", name)
			command = command2
			defer cancelCommand3()
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
		command, cancelCommand4 := commandContext(longTimeout, "mariadb-dump", "--single-transaction", "--routines", "--triggers", "--result-file="+destination, database.Name)
		defer cancelCommand4()
		if database.Engine == "MySQL" {
			command2, cancelCommand5 := commandContext(longTimeout, "mysqldump", "--single-transaction", "--routines", "--triggers", "--result-file="+destination, database.Name)
			command = command2
			defer cancelCommand5()
		} else if database.Engine == "PostgreSQL" {
			command2, cancelCommand6 := commandContext(longTimeout, "runuser", "-u", "postgres", "--", "pg_dump", "--clean", "--if-exists", "--file", destination, database.Name)
			command = command2
			defer cancelCommand6()
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
	if output, err := runLong("tar", paths...); err != nil {
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

// detectServerIPs returns the local interface addresses plus the detected
// public address. detectPublicAddress makes an external HTTP call, so callers
// that inspect many domains should compute this once and reuse it rather than
// paying the round-trip per domain.
func detectServerIPs() []string {
	ips := localIPs()
	if detected, err := detectPublicAddress(); err == nil {
		if publicIP := detected["address"]; publicIP != "" {
			alreadyPresent := false
			for _, address := range ips {
				if address == publicIP {
					alreadyPresent = true
				}
			}
			if !alreadyPresent {
				ips = append(ips, publicIP)
				sort.Strings(ips)
			}
		}
	}
	return ips
}

func listTLS() ([]tlsStatus, error) {
	sites, err := listSites()
	if err != nil {
		return nil, err
	}
	// Detect the public address once (one external call) and resolve every
	// domain concurrently, instead of one blocking round-trip per site.
	serverIPs := detectServerIPs()
	statuses := make([]tlsStatus, len(sites))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 8)
	for index, value := range sites {
		wg.Add(1)
		go func(index int, domain string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			statuses[index] = inspectTLSWithServerIPs(domain, serverIPs)
		}(index, value.Domain)
	}
	wg.Wait()
	return statuses, nil
}

func inspectTLS(domain string) tlsStatus {
	return inspectTLSWithServerIPs(domain, detectServerIPs())
}

func inspectTLSWithServerIPs(domain string, serverIPs []string) tlsStatus {
	// Copy so concurrent callers never share a backing array.
	ips := append([]string(nil), serverIPs...)
	status := tlsStatus{Domain: domain, DNSAddresses: []string{}, ServerIPs: ips}
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
		if output, err := runOutputWithTimeout(defaultTimeout, "openssl", "x509", "-in", certificatePath, "-noout", "-enddate"); err == nil {
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

func issueTLS(domain, email string, force bool) (tlsStatus, error) {
	if os.Geteuid() != 0 {
		return tlsStatus{}, errors.New("tls-issue must run as root")
	}
	domain, email = strings.ToLower(strings.TrimSpace(domain)), strings.TrimSpace(email)
	if !domainPattern.MatchString(domain) {
		return tlsStatus{}, errors.New("invalid domain")
	}
	// Email is only required for the very first issuance (account registration).
	// A renewal (force) reuses the existing ACME account, so it may be omitted.
	if email != "" && !regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`).MatchString(email) {
		return tlsStatus{}, errors.New("invalid email address")
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
	// --force-renewal and --keep-until-expiring are mutually exclusive.
	renewalFlag := "--keep-until-expiring"
	if force {
		renewalFlag = "--force-renewal"
	}
	buildArgs := func(withWWW bool) []string {
		var args []string
		if webServer == "apache" {
			args = []string{"--apache", "--non-interactive", "--agree-tos", renewalFlag, "--redirect"}
		} else {
			args = []string{"certonly", "--nginx", "--non-interactive", "--agree-tos", renewalFlag}
		}
		if email != "" {
			args = append(args, "--email", email)
		}
		args = append(args, "--domain", normaliseHost(domain))
		if withWWW {
			if alias, ok := wwwAliasFor(domain); ok {
				args = append(args, "--domain", alias)
			}
		}
		return args
	}
	if force {
		_ = writeAudit("tls.renew.started", true, domain)
	} else {
		_ = writeAudit("tls.issue.started", true, domain)
	}

	// Only attempt the www name when the domain actually has one. Asking for
	// www.blog.example.com always fails validation, and Let's Encrypt allows
	// just five failures per hostname per hour — a budget worth not spending on
	// a request that cannot succeed.
	_, hasWWW := wwwAliasFor(domain)
	if output, err := runLong("certbot", buildArgs(hasWWW)...); err != nil {
		// A registrable domain whose www record simply is not pointed here yet:
		// retry with the bare name so the site still gets a certificate.
		if !hasWWW {
			_ = atomicWrite(configPath, original, 0644)
			_, _ = run("systemctl", "reload", map[string]string{"nginx": "nginx", "apache": "apache2"}[webServer])
			_ = writeAudit("tls.issue.failed", false, domain+": "+tail(string(output), 800))
			return readiness, fmt.Errorf("Certbot failed: %s", tail(string(output), 800))
		}
		if fallbackOutput, fallbackErr := runLong("certbot", buildArgs(false)...); fallbackErr != nil {
			_ = atomicWrite(configPath, original, 0644)
			_, _ = run("systemctl", "reload", map[string]string{"nginx": "nginx", "apache": "apache2"}[webServer])
			_ = writeAudit("tls.issue.failed", false, domain+": "+tail(string(output)+"\nFallback: "+string(fallbackOutput), 800))
			return readiness, fmt.Errorf("Certbot failed: %s", tail(string(output), 800))
		}
	}
	if webServer == "apache" {
		if output, err := run("apache2ctl", "configtest"); err != nil {
			_ = writeAudit("tls.issue.failed", false, domain+": "+tail(string(output), 800))
			return readiness, fmt.Errorf("Apache TLS validation failed: %s", tail(string(output), 800))
		}
		if err := mustRun("systemctl", "reload", "apache2"); err != nil {
			return readiness, err
		}
		_ = writeAudit("tls.issue.completed", true, domain)
		return inspectTLS(domain), nil
	}
	if err := configureNginxTLS(domain, configPath, original); err != nil {
		return readiness, err
	}
	_ = writeAudit("tls.issue.completed", true, domain)
	return inspectTLS(domain), nil
}

func configureNginxTLS(domain, configPath string, original []byte) error {
	certificatePath := filepath.Join("/etc/letsencrypt/live", domain)
	// See nginxtls.go: this replaces a blind insert into the first server block,
	// which stopped being the serving block once canonical redirects existed, and
	// it adds the HTTP to HTTPS redirect certonly never writes.
	updated, err := nginxTLSConfig(string(original), domain, certificatePath, canonicalNonWWW)
	if err != nil {
		return err
	}
	if err := atomicWrite(configPath, []byte(updated), 0644); err != nil {
		return err
	}
	rollback := func() {
		_ = atomicWrite(configPath, original, 0644)
		_, _ = run("systemctl", "reload", "nginx")
	}
	if output, err := run("nginx", "-t"); err != nil {
		rollback()
		return fmt.Errorf("Nginx TLS validation failed: %s", tail(string(output), 800))
	}
	if err := mustRun("systemctl", "reload", "nginx"); err != nil {
		rollback()
		return err
	}
	return nil
}

type certificateDetail struct {
	Domain        string   `json:"domain"`
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	Domains       []string `json:"domains"`
	NotBefore     string   `json:"notBefore"`
	NotAfter      string   `json:"notAfter"`
	DaysRemaining int      `json:"daysRemaining"`
	Serial        string   `json:"serial"`
	KeyType       string   `json:"keyType"`
	Fingerprint   string   `json:"fingerprint"`
}

func detailTLS(domain string) (certificateDetail, error) {
	detail := certificateDetail{}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) {
		return detail, errors.New("invalid domain")
	}
	if _, err := os.Stat(filepath.Join("/var/lib/serverdeck/sites", domain+".json")); err != nil {
		return detail, errors.New("managed website was not found")
	}
	contents, err := os.ReadFile(filepath.Join("/etc/letsencrypt/live", domain, "cert.pem"))
	if err != nil {
		return detail, errors.New("no certificate is installed for this domain")
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return detail, errors.New("the certificate file could not be parsed")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return detail, err
	}
	detail.Domain = domain
	detail.Subject = certificate.Subject.CommonName
	detail.Issuer = strings.TrimSpace(strings.Join(append(certificate.Issuer.Organization, certificate.Issuer.CommonName), " "))
	detail.Domains = append([]string{}, certificate.DNSNames...)
	sort.Strings(detail.Domains)
	detail.NotBefore = certificate.NotBefore.UTC().Format(time.RFC1123)
	detail.NotAfter = certificate.NotAfter.UTC().Format(time.RFC1123)
	detail.DaysRemaining = int(time.Until(certificate.NotAfter).Hours() / 24)
	detail.Serial = certificate.SerialNumber.Text(16)
	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		detail.KeyType = fmt.Sprintf("RSA %d-bit", key.N.BitLen())
	case *ecdsa.PublicKey:
		detail.KeyType = fmt.Sprintf("ECDSA %s", key.Curve.Params().Name)
	default:
		detail.KeyType = certificate.PublicKeyAlgorithm.String()
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	detail.Fingerprint = fmt.Sprintf("%x", fingerprint)
	return detail, nil
}

// stripNginxTLS removes the HTTPS directives that configureNginxTLS inserted,
// returning an HTTP-only configuration.
func stripNginxTLS(config string) string {
	lines := strings.Split(config, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "listen 443") || strings.HasPrefix(trimmed, "listen [::]:443") || strings.HasPrefix(trimmed, "ssl_certificate") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// stripApacheCertbotRedirect removes the HTTP-to-HTTPS redirect directives the
// certbot Apache installer adds to the port-80 virtual host. ServerDeck
// generates these site configurations, so the only rewrite rules present are
// the certbot-inserted redirect trio.
func stripApacheCertbotRedirect(config string) string {
	lines := strings.Split(config, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "RewriteEngine on" || strings.HasPrefix(trimmed, "RewriteCond %{SERVER_NAME}") || strings.HasPrefix(trimmed, "RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI}") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func removeTLS(domain string) (tlsStatus, error) {
	if os.Geteuid() != 0 {
		return tlsStatus{}, errors.New("tls-remove must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) {
		return tlsStatus{}, errors.New("invalid domain")
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
	status := inspectTLS(domain)
	if !status.Certificate {
		return status, errors.New("no certificate is installed for this domain")
	}
	webServer := managedSite.WebServer
	if webServer == "" {
		webServer = "nginx"
	}
	_ = writeAudit("tls.remove.started", true, domain)
	if webServer == "apache" {
		configPath := filepath.Join("/etc/apache2/sites-available", domain+".conf")
		original, readErr := os.ReadFile(configPath)
		if readErr != nil {
			return status, readErr
		}
		_, _ = run("a2dissite", domain+"-le-ssl")
		if err := atomicWrite(configPath, []byte(stripApacheCertbotRedirect(string(original))), 0644); err != nil {
			return status, err
		}
		rollback := func() {
			_ = atomicWrite(configPath, original, 0644)
			_, _ = run("a2ensite", domain+"-le-ssl")
			_, _ = run("systemctl", "reload", "apache2")
		}
		if output, err := run("apache2ctl", "configtest"); err != nil {
			rollback()
			_ = writeAudit("tls.remove.failed", false, domain+": "+tail(string(output), 800))
			return status, fmt.Errorf("Apache validation failed: %s", tail(string(output), 800))
		}
		if err := mustRun("systemctl", "reload", "apache2"); err != nil {
			rollback()
			return status, err
		}
		_ = os.Remove(filepath.Join("/etc/apache2/sites-available", domain+"-le-ssl.conf"))
	} else {
		configPath := filepath.Join("/etc/nginx/sites-available", domain)
		original, readErr := os.ReadFile(configPath)
		if readErr != nil {
			return status, readErr
		}
		if err := atomicWrite(configPath, []byte(stripNginxTLS(string(original))), 0644); err != nil {
			return status, err
		}
		rollback := func() {
			_ = atomicWrite(configPath, original, 0644)
			_, _ = run("systemctl", "reload", "nginx")
		}
		if output, err := run("nginx", "-t"); err != nil {
			rollback()
			_ = writeAudit("tls.remove.failed", false, domain+": "+tail(string(output), 800))
			return status, fmt.Errorf("Nginx validation failed: %s", tail(string(output), 800))
		}
		if err := mustRun("systemctl", "reload", "nginx"); err != nil {
			rollback()
			return status, err
		}
	}
	// Delete certificate material only after the web server stopped referencing
	// it, so a rollback above never points at missing files.
	if output, err := runLong("certbot", "delete", "--cert-name", domain, "--non-interactive"); err != nil {
		_ = writeAudit("tls.remove.failed", false, domain+": "+tail(string(output), 800))
		return inspectTLS(domain), fmt.Errorf("HTTPS was disabled, but Certbot could not delete the certificate: %s", tail(string(output), 800))
	}
	_ = writeAudit("tls.remove.completed", true, domain)
	return inspectTLS(domain), nil
}

type dnsChallenge struct {
	Domain     string `json:"domain"`
	Validation string `json:"validation"`
}

var dnsSessionPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// certbotMajorVersion parses `certbot --version` ("certbot 0.40.0"). It
// returns 2 when detection fails so modern flag behavior is the default.
func certbotMajorVersion() int {
	output, err := runLong("certbot", "--version")
	if err != nil {
		return 2
	}
	fields := strings.Fields(strings.TrimSpace(string(output)))
	if len(fields) == 0 {
		return 2
	}
	parts := strings.SplitN(fields[len(fields)-1], ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 2
	}
	return major
}

func dnsSessionDirectory(session string) (string, error) {
	if !dnsSessionPattern.MatchString(session) {
		return "", errors.New("invalid DNS validation session")
	}
	return filepath.Join("/run/serverdeck/acme", session), nil
}

func waitForDNSChallenge(session string) (map[string]bool, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("tls-dns-auth must run as root")
	}
	directory, err := dnsSessionDirectory(session)
	if err != nil {
		return nil, err
	}
	domain := strings.ToLower(strings.TrimSpace(os.Getenv("CERTBOT_DOMAIN")))
	validation := strings.TrimSpace(os.Getenv("CERTBOT_VALIDATION"))
	if !domainPattern.MatchString(domain) || validation == "" || len(validation) > 1024 {
		return nil, errors.New("Certbot did not provide a valid DNS challenge")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	contents, _ := json.Marshal(dnsChallenge{Domain: domain, Validation: validation})
	if err := atomicWrite(filepath.Join(directory, "challenge.json"), append(contents, '\n'), 0600); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 480; attempt++ {
		if _, err := os.Stat(filepath.Join(directory, "abort")); err == nil {
			return nil, errors.New("DNS challenge publication failed on the Mac")
		}
		if _, err := os.Stat(filepath.Join(directory, "ready")); err == nil {
			return map[string]bool{"ready": true}, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil, errors.New("timed out waiting for DNS challenge publication")
}

func continueDNSChallenge(session string, abort bool) (map[string]bool, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("DNS challenge control must run as root")
	}
	directory, err := dnsSessionDirectory(session)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(directory); err != nil {
		return nil, errors.New("DNS validation session was not found")
	}
	name := "ready"
	if abort {
		name = "abort"
	}
	if err := atomicWrite(filepath.Join(directory, name), []byte("1\n"), 0600); err != nil {
		return nil, err
	}
	return map[string]bool{name: true}, nil
}

func issueTLSDNS(domain, email, session string, force bool) (tlsStatus, error) {
	if os.Geteuid() != 0 {
		return tlsStatus{}, errors.New("tls-dns-issue must run as root")
	}
	domain, email = strings.ToLower(strings.TrimSpace(domain)), strings.TrimSpace(email)
	if !domainPattern.MatchString(domain) {
		return tlsStatus{}, errors.New("invalid domain")
	}
	// Email is only required for first issuance; a renewal reuses the account.
	if email != "" && !regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`).MatchString(email) {
		return tlsStatus{}, errors.New("invalid email address")
	}
	directory, err := dnsSessionDirectory(session)
	if err != nil {
		return tlsStatus{}, err
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
	if managedSite.WebServer != "" && managedSite.WebServer != "nginx" {
		return tlsStatus{}, errors.New("Cloudflare DNS validation currently supports Nginx websites; use direct DNS validation for Apache")
	}
	configPath := filepath.Join("/etc/nginx/sites-available", domain)
	original, err := os.ReadFile(configPath)
	if err != nil {
		return tlsStatus{}, err
	}
	_ = os.RemoveAll(directory)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return tlsStatus{}, err
	}
	defer os.RemoveAll(directory)
	hookBinary := "/usr/local/bin/serverdeck-agent"
	if executable, executableErr := os.Executable(); executableErr == nil && !strings.ContainsAny(executable, " \t\"'\\") {
		hookBinary = executable
	}
	// The hook path must not be quoted: certbot 0.40 (Ubuntu 20.04) validates
	// the first whitespace-separated token literally, so quotes make it
	// report "Unable to find manual-auth-hook command ... in the PATH".
	authHook := fmt.Sprintf("%s tls-dns-auth %s", hookBinary, session)
	cleanupHook := fmt.Sprintf("%s tls-dns-cleanup %s", hookBinary, session)
	renewalFlag := "--keep-until-expiring"
	if force {
		renewalFlag = "--force-renewal"
	}
	arguments := []string{"certonly", "--manual", "--preferred-challenges", "dns", "--manual-auth-hook", authHook, "--manual-cleanup-hook", cleanupHook, "--non-interactive", "--agree-tos", renewalFlag, "--domain", domain}
	if email != "" {
		arguments = append(arguments, "--email", email)
	}
	if certbotMajorVersion() < 2 {
		// Required by certbot < 2.0 for non-interactive manual mode; the
		// flag was removed in certbot 2.0 and would be rejected there.
		arguments = append(arguments, "--manual-public-ip-logging-ok")
	}
	command, cancelCommand7 := commandContext(longTimeout, "certbot", arguments...)
	defer cancelCommand7()
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		return tlsStatus{}, fmt.Errorf("start Certbot: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	challengeReported := false
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(6 * time.Minute)
	defer timeout.Stop()
	for {
		select {
		case commandErr := <-done:
			if commandErr != nil {
				_ = writeAudit("tls.issue.failed", false, domain+": "+tail(output.String(), 1200))
				return tlsStatus{}, fmt.Errorf("Certbot DNS validation failed: %s", tail(output.String(), 1200))
			}
			if err := configureNginxTLS(domain, configPath, original); err != nil {
				return tlsStatus{}, err
			}
			_ = writeAudit("tls.issue.completed", true, domain+" via DNS-01")
			return inspectTLS(domain), nil
		case <-ticker.C:
			if challengeReported {
				continue
			}
			contents, readErr := os.ReadFile(filepath.Join(directory, "challenge.json"))
			if readErr != nil {
				continue
			}
			var challenge dnsChallenge
			if json.Unmarshal(contents, &challenge) == nil && challenge.Validation != "" {
				fmt.Printf("SERVERDECK_ACME_DNS|%s|_acme-challenge.%s|%s\n", session, challenge.Domain, challenge.Validation)
				_ = os.Stdout.Sync()
				challengeReported = true
			}
		case <-timeout.C:
			_ = command.Process.Kill()
			return tlsStatus{}, errors.New("Certbot DNS validation timed out")
		}
	}
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
		// Read from stdin so the password never appears in the process list.
		if output, err := runWithStdin(defaultTimeout, roleSQL, "runuser", "-u", "postgres", "--", "psql", "--set", "ON_ERROR_STOP=1", "--file", "-"); err != nil {
			_ = writeAudit("database.create.failed", false, name+": "+tail(string(output), 500))
			return value, fmt.Errorf("PostgreSQL rejected role creation: %s", tail(string(output), 500))
		}
		if output, err := run("runuser", "-u", "postgres", "--", "createdb", "--owner", username, name); err != nil {
			_, _ = run("runuser", "-u", "postgres", "--", "dropuser", "--if-exists", username)
			_ = writeAudit("database.create.failed", false, name+": "+tail(string(output), 500))
			return value, fmt.Errorf("PostgreSQL rejected database creation: %s", tail(string(output), 500))
		}
	} else {
		sql := fmt.Sprintf("CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER '%s'@'localhost' IDENTIFIED BY '%s'; GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost'; FLUSH PRIVILEGES;", name, username, password, name, username)
		// Through stdin, not --execute: an argument holding the password would be
		// readable in /proc by any local user, www-data included. See runWithStdin.
		if output, err := runWithStdin(defaultTimeout, sql, databaseClient, "--batch", "--skip-column-names"); err != nil {
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
			_, _ = run("runuser", "-u", "postgres", "--", "dropdb", "--if-exists", name)
			_, _ = run("runuser", "-u", "postgres", "--", "dropuser", "--if-exists", username)
		} else {
			cleanup := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`; DROP USER IF EXISTS '%s'@'localhost';", name, username)
			_, _ = run(databaseClient, "--execute", cleanup)
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
	output, err := runOutputWithTimeout(defaultTimeout, "dpkg-query", "-W", "-f=${Status}\t${Version}", name)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(strings.TrimSpace(string(output)), "\t", 2)
	if len(parts) == 2 && strings.HasPrefix(parts[0], "install ok installed") {
		return parts[1]
	}
	return ""
}

func listMailDomainsAndAccounts() []mailDomainInfo {
	domainsMap := make(map[string]*mailDomainInfo)

	if vhostsBytes, err := os.ReadFile("/etc/postfix/vhosts"); err == nil {
		lines := strings.Split(string(vhostsBytes), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) > 0 {
				domain := strings.ToLower(parts[0])
				dkimReady := false
				if _, statErr := os.Stat(filepath.Join("/etc/opendkim/keys", domain, "mail.private")); statErr == nil {
					dkimReady = true
				}
				domainsMap[domain] = &mailDomainInfo{
					Domain:    domain,
					DKIMReady: dkimReady,
					Accounts:  []string{},
					Aliases:   []mailAliasInfo{},
				}
			}
		}
	}

	if vmapsBytes, err := os.ReadFile("/etc/postfix/vmaps"); err == nil {
		lines := strings.Split(string(vmapsBytes), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) > 0 {
				email := strings.ToLower(parts[0])
				idx := strings.Index(email, "@")
				if idx > 0 && idx < len(email)-1 {
					domain := email[idx+1:]
					if info, exists := domainsMap[domain]; exists {
						info.Accounts = append(info.Accounts, email)
					}
				}
			}
		}
	}

	if virtualBytes, err := os.ReadFile("/etc/postfix/virtual"); err == nil {
		lines := strings.Split(string(virtualBytes), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				source := strings.ToLower(parts[0])
				dest := strings.Join(parts[1:], " ")
				var domain string
				if strings.HasPrefix(source, "@") {
					domain = source[1:]
				} else {
					idx := strings.Index(source, "@")
					if idx > 0 && idx < len(source)-1 {
						domain = source[idx+1:]
					}
				}
				if domain != "" {
					if info, exists := domainsMap[domain]; exists {
						info.Aliases = append(info.Aliases, mailAliasInfo{
							Source:      source,
							Destination: dest,
						})
					}
				}
			}
		}
	}

	domainsList := make([]mailDomainInfo, 0, len(domainsMap))
	for _, info := range domainsMap {
		sort.Strings(info.Accounts)
		sort.Slice(info.Aliases, func(i, j int) bool {
			return info.Aliases[i].Source < info.Aliases[j].Source
		})
		domainsList = append(domainsList, *info)
	}

	sort.Slice(domainsList, func(i, j int) bool {
		return domainsList[i].Domain < domainsList[j].Domain
	})

	return domainsList
}

func inspectMail() (mailStatus, error) {
	hostname, _ := os.Hostname()
	status := mailStatus{
		Hostname:         hostname,
		PostfixInstalled: packageVersion("postfix") != "",
		PostfixActive:    unitActive("postfix"),
		DovecotInstalled: packageVersion("dovecot-core") != "",
		DovecotActive:    unitActive("dovecot"),
		Domains:          []mailDomainInfo{},
	}
	if value, err := os.ReadFile("/etc/mailname"); err == nil {
		status.Mailname = strings.TrimSpace(string(value))
	}
	status.ReadyForSetup = status.PostfixInstalled && status.PostfixActive && status.DovecotInstalled && status.DovecotActive
	if status.ReadyForSetup {
		status.Domains = listMailDomainsAndAccounts()
	}
	return status, nil
}

func inspectContainers() (containerInventory, error) {
	result := containerInventory{Installed: packageVersion("docker.io") != "", Active: unitActive("docker"), Containers: []containerStatus{}}
	if !result.Installed {
		return result, nil
	}
	if output, err := runOutputWithTimeout(defaultTimeout, "docker", "version", "--format", "{{.Server.Version}}"); err == nil {
		result.Version = strings.TrimSpace(string(output))
	}
	if !result.Active {
		return result, nil
	}
	output, err := run("docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}")
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
	command, cancelCommand8 := commandContext(longTimeout, "apt-get", "install", "-y", "--no-install-recommends", "docker.io")
	defer cancelCommand8()
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	output, err := command.CombinedOutput()
	if err != nil {
		return containerInventory{}, fmt.Errorf("install Docker: %s", tail(string(output), 1200))
	}
	if output, err := run("systemctl", "enable", "--now", "docker"); err != nil {
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
	output, err := run("docker", action, "--", name)
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
	output, err := run("docker", "logs", "--tail", strconv.Itoa(lines), "--", name)
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

func getFileMetadata(info os.FileInfo) (mode string, perm string, owner string, group string) {
	mode = info.Mode().String()
	perm = fmt.Sprintf("%04o", info.Mode().Perm())
	owner = "unknown"
	group = "unknown"

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uidStr := fmt.Sprintf("%d", stat.Uid)
		gidStr := fmt.Sprintf("%d", stat.Gid)

		if u, err := user.LookupId(uidStr); err == nil {
			owner = u.Username
		} else {
			owner = uidStr
		}

		if g, err := user.LookupGroupId(gidStr); err == nil {
			group = g.Name
		} else {
			group = gidStr
		}
	}
	return
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
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		relative, _ := filepath.Rel(root, filepath.Join(target, entry.Name()))
		m, p, o, g := getFileMetadata(info)
		values = append(values, managedFile{
			Name:      entry.Name(),
			Path:      filepath.ToSlash(relative),
			Directory: entry.IsDir(),
			Size:      info.Size(),
			Modified:  info.ModTime().UTC().Format(time.RFC3339),
			Mode:      m,
			Perm:      p,
			Owner:     o,
			Group:     g,
		})
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
	if err := replaceManagedFile(root, target, content); err != nil {
		return fileContents{}, err
	}
	_ = writeAudit("file.updated", true, target)
	return readManagedFileEncoded(domain, path)
}

func deleteManagedFileEncoded(domain, path, permanentStr string) ([]managedFile, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("file-delete must run as root")
	}
	permanent := false
	if permanentStr == "true" {
		permanent = true
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

	if permanent {
		if err := os.RemoveAll(target); err != nil {
			return nil, err
		}
		_ = writeAudit("file.deleted_permanently", true, target)
	} else {
		trashDir, err := managedTrashDirectory(root)
		if err != nil {
			return nil, err
		}

		timestamp := time.Now().UnixNano()
		name := filepath.Base(target)
		trashName := fmt.Sprintf("%s_%d", name, timestamp)
		trashPath := filepath.Join(trashDir, trashName)

		if err := os.Rename(target, trashPath); err != nil {
			return nil, err
		}

		manifestPath := filepath.Join(trashDir, "manifest.json")
		var manifest []trashEntry
		if bytes, err := os.ReadFile(manifestPath); err == nil {
			_ = json.Unmarshal(bytes, &manifest)
		}

		relative, _ := filepath.Rel(root, target)
		manifest = append(manifest, trashEntry{
			TrashName:    trashName,
			OriginalPath: filepath.ToSlash(relative),
			DeletedAt:    time.Now().UTC().Format(time.RFC3339),
			Directory:    info.IsDir(),
		})

		if data, err := json.MarshalIndent(manifest, "", "  "); err == nil {
			_ = atomicWrite(manifestPath, append(data, '\n'), 0600)
		}
		_ = writeAudit("file.trashed", true, target)
	}

	parent, _ := filepath.Rel(root, filepath.Dir(target))
	if parent == "." {
		parent = ""
	}
	return listManagedFilesEncoded(domain, base64.RawURLEncoding.EncodeToString([]byte(parent)))
}

func listTrashedFilesEncoded(domain string) ([]trashEntry, error) {
	root, _, err := managedSitePath(domain, "")
	if err != nil {
		return nil, err
	}
	trashDir, err := managedTrashDirectory(root)
	if err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(trashDir, "manifest.json")
	var manifest []trashEntry
	if bytes, err := os.ReadFile(manifestPath); err == nil {
		_ = json.Unmarshal(bytes, &manifest)
	} else {
		manifest = []trashEntry{}
	}
	return manifest, nil
}

func restoreTrashedFileEncoded(domain, trashName string) ([]trashEntry, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("file-trash-restore must run as root")
	}
	decodedTrashName, err := decodeArgument(trashName)
	if err != nil {
		return nil, err
	}
	root, _, err := managedSitePath(domain, "")
	if err != nil {
		return nil, err
	}
	trashDir, err := managedTrashDirectory(root)
	if err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(trashDir, "manifest.json")

	var manifest []trashEntry
	if bytes, err := os.ReadFile(manifestPath); err == nil {
		_ = json.Unmarshal(bytes, &manifest)
	} else {
		return nil, errors.New("trash manifest not found")
	}

	foundIdx := -1
	var entry trashEntry
	for i, item := range manifest {
		if item.TrashName == decodedTrashName {
			foundIdx = i
			entry = item
			break
		}
	}

	if foundIdx == -1 {
		return nil, errors.New("item not found in trash")
	}
	if !validTrashName(decodedTrashName) {
		return nil, errors.New("trash entry has an unsafe name")
	}

	trashPath := filepath.Join(trashDir, decodedTrashName)
	originalPath, err := managedRestoreTarget(root, entry.OriginalPath)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(originalPath); err == nil {
		return nil, fmt.Errorf("an item already exists at original location: %s", entry.OriginalPath)
	}

	if err := os.MkdirAll(filepath.Dir(originalPath), 0755); err != nil {
		return nil, err
	}

	if err := os.Rename(trashPath, originalPath); err != nil {
		return nil, err
	}

	manifest = append(manifest[:foundIdx], manifest[foundIdx+1:]...)
	if data, err := json.MarshalIndent(manifest, "", "  "); err == nil {
		_ = atomicWrite(manifestPath, append(data, '\n'), 0600)
	}
	_ = writeAudit("file.restored", true, originalPath)

	return manifest, nil
}

func emptyTrashEncoded(domain string) ([]trashEntry, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("file-trash-empty must run as root")
	}
	root, _, err := managedSitePath(domain, "")
	if err != nil {
		return nil, err
	}
	trashDir, err := managedTrashDirectory(root)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(trashDir); err != nil {
		return []trashEntry{}, nil
	}

	entries, err := os.ReadDir(trashDir)
	if err == nil {
		for _, entry := range entries {
			_ = os.RemoveAll(filepath.Join(trashDir, entry.Name()))
		}
	}

	manifestPath := filepath.Join(trashDir, "manifest.json")
	_ = atomicWrite(manifestPath, []byte("[]\n"), 0600)

	_ = writeAudit("file.trash_emptied", true, trashDir)
	return []trashEntry{}, nil
}

func createManagedDirEncoded(domain, path string) ([]managedFile, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("file-create-dir must run as root")
	}
	root, target, err := managedSitePath(domain, path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(target); err == nil {
		return nil, errors.New("a file or folder with this name already exists")
	}
	if err := os.MkdirAll(target, 0755); err != nil {
		return nil, err
	}
	parent := filepath.Dir(target)
	if stat, err := os.Stat(parent); err == nil {
		if sysStat, ok := stat.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(target, int(sysStat.Uid), int(sysStat.Gid))
		}
	}
	_ = writeAudit("file.create_dir", true, target)

	parentRel, _ := filepath.Rel(root, parent)
	if parentRel == "." {
		parentRel = ""
	}
	return listManagedFilesEncoded(domain, base64.RawURLEncoding.EncodeToString([]byte(parentRel)))
}

func createManagedFileEncoded(domain, path string) ([]managedFile, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("file-create-file must run as root")
	}
	root, target, err := managedSitePath(domain, path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(target); err == nil {
		return nil, errors.New("a file or folder with this name already exists")
	}
	if err := atomicWrite(target, []byte(""), 0644); err != nil {
		return nil, err
	}
	parent := filepath.Dir(target)
	if stat, err := os.Stat(parent); err == nil {
		if sysStat, ok := stat.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(target, int(sysStat.Uid), int(sysStat.Gid))
		}
	}
	_ = writeAudit("file.create_file", true, target)

	parentRel, _ := filepath.Rel(root, parent)
	if parentRel == "." {
		parentRel = ""
	}
	return listManagedFilesEncoded(domain, base64.RawURLEncoding.EncodeToString([]byte(parentRel)))
}

func chmodManagedFileEncoded(domain, path, encodedMode string) ([]managedFile, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("file-chmod must run as root")
	}
	modeStr, err := decodeArgument(encodedMode)
	if err != nil {
		return nil, err
	}
	modeVal, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return nil, errors.New("invalid permission mode (must be octal e.g. 0644)")
	}
	root, target, err := managedSitePath(domain, path)
	if err != nil {
		return nil, err
	}
	if target == root {
		return nil, errors.New("the website root permissions cannot be modified")
	}
	if modeVal > 0777 {
		return nil, errors.New("permission mode must be between 0000 and 0777")
	}
	if err := chmodManagedTarget(root, target, os.FileMode(modeVal)); err != nil {
		return nil, err
	}
	_ = writeAudit("file.chmod", true, target)

	parent := filepath.Dir(target)
	parentRel, _ := filepath.Rel(root, parent)
	if parentRel == "." {
		parentRel = ""
	}
	return listManagedFilesEncoded(domain, base64.RawURLEncoding.EncodeToString([]byte(parentRel)))
}

func chownManagedFileEncoded(domain, path, encodedOwner, encodedGroup string) ([]managedFile, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("file-chown must run as root")
	}
	ownerStr, err := decodeArgument(encodedOwner)
	if err != nil {
		return nil, err
	}
	groupStr, err := decodeArgument(encodedGroup)
	if err != nil {
		return nil, err
	}
	root, target, err := managedSitePath(domain, path)
	if err != nil {
		return nil, err
	}
	if target == root {
		return nil, errors.New("the website root ownership cannot be modified")
	}

	uid := -1
	if ownerStr != "" {
		if u, err := user.Lookup(ownerStr); err == nil {
			if parsedUid, err := strconv.Atoi(u.Uid); err == nil {
				uid = parsedUid
			}
		} else if parsedUid, err := strconv.Atoi(ownerStr); err == nil {
			uid = parsedUid
		} else {
			return nil, fmt.Errorf("user not found: %s", ownerStr)
		}
	}

	gid := -1
	if groupStr != "" {
		if g, err := user.LookupGroup(groupStr); err == nil {
			if parsedGid, err := strconv.Atoi(g.Gid); err == nil {
				gid = parsedGid
			}
		} else if parsedGid, err := strconv.Atoi(groupStr); err == nil {
			gid = parsedGid
		} else {
			return nil, fmt.Errorf("group not found: %s", groupStr)
		}
	}

	if err := chownManagedTarget(root, target, uid, gid); err != nil {
		return nil, err
	}
	_ = writeAudit("file.chown", true, target)

	parent := filepath.Dir(target)
	parentRel, _ := filepath.Rel(root, parent)
	if parentRel == "." {
		parentRel = ""
	}
	return listManagedFilesEncoded(domain, base64.RawURLEncoding.EncodeToString([]byte(parentRel)))
}

func configureMailFoundation() error {
	_, _ = run("groupadd", "-g", "5000", "vmail")
	_, _ = run("useradd", "-g", "vmail", "-u", "5000", "vmail", "-d", "/var/mail/vhosts", "-m", "-s", "/usr/sbin/nologin")

	_ = os.MkdirAll("/var/mail/vhosts", 0770)
	_, _ = run("chown", "-R", "vmail:vmail", "/var/mail/vhosts")

	for _, file := range []string{"/etc/postfix/vhosts", "/etc/postfix/vmaps", "/etc/postfix/virtual", "/etc/dovecot/users"} {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			_ = os.WriteFile(file, []byte(""), 0600)
		}
	}
	_, _ = run("chown", "root:root", "/etc/postfix/vhosts", "/etc/postfix/vmaps", "/etc/postfix/virtual")
	_ = os.Chmod("/etc/postfix/vhosts", 0600)
	_ = os.Chmod("/etc/postfix/vmaps", 0600)
	_ = os.Chmod("/etc/postfix/virtual", 0600)
	_, _ = run("chown", "dovecot:dovecot", "/etc/dovecot/users")
	_ = os.Chmod("/etc/dovecot/users", 0600)

	postfixSettings := []string{
		"virtual_mailbox_domains = hash:/etc/postfix/vhosts",
		"virtual_mailbox_maps = hash:/etc/postfix/vmaps",
		"virtual_alias_maps = hash:/etc/postfix/virtual",
		"virtual_transport = lmtp:unix:private/dovecot-lmtp",
		"smtpd_sasl_type = dovecot",
		"smtpd_sasl_path = private/auth",
		"smtpd_sasl_auth_enable = yes",
		"smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination",
	}
	for _, setting := range postfixSettings {
		_, _ = run("postconf", "-e", setting)
	}

	mailConf := "mail_location = maildir:/var/mail/vhosts/%d/%n\nnamespace inbox {\n  inbox = yes\n}\n"
	_ = os.WriteFile("/etc/dovecot/conf.d/10-mail.conf", []byte(mailConf), 0644)

	authConf := "disable_plaintext_auth = yes\nauth_mechanisms = plain login\n!include auth-passwdfile.conf.ext\n"
	_ = os.WriteFile("/etc/dovecot/conf.d/10-auth.conf", []byte(authConf), 0644)

	authExt := "passdb {\n  driver = passwd-file\n  args = scheme=SHA512-CRYPT username_format=%u /etc/dovecot/users\n}\nuserdb {\n  driver = passwd-file\n  args = username_format=%u /etc/dovecot/users\n}\n"
	_ = os.WriteFile("/etc/dovecot/conf.d/auth-passwdfile.conf.ext", []byte(authExt), 0644)

	masterConf := "service lmtp {\n  unix_listener private/dovecot-lmtp {\n    mode = 0660\n    group = postfix\n    user = postfix\n  }\n}\nservice auth {\n  unix_listener private/auth {\n    mode = 0660\n    user = postfix\n    group = postfix\n  }\n}\n"
	_ = os.WriteFile("/etc/dovecot/conf.d/10-master.conf", []byte(masterConf), 0644)

	_, _ = run("postmap", "/etc/postfix/vhosts")
	_, _ = run("postmap", "/etc/postfix/vmaps")
	_, _ = run("postmap", "/etc/postfix/virtual")
	return nil
}

func installMailStack() (mailStatus, error) {
	if os.Geteuid() != 0 {
		return mailStatus{}, errors.New("mail-stack-install must run as root")
	}
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return mailStatus{}, errors.New("the server hostname is not configured")
	}
	command, cancelCommand9 := commandContext(longTimeout, "apt-get", "install", "-y", "--no-install-recommends", "postfix", "dovecot-core", "dovecot-imapd", "dovecot-lmtpd")
	defer cancelCommand9()
	command.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	output, err := command.CombinedOutput()
	if err != nil {
		return mailStatus{}, fmt.Errorf("install mail foundation: %s", tail(string(output), 1200))
	}

	if err := configureMailFoundation(); err != nil {
		return mailStatus{}, fmt.Errorf("configure mail foundation: %w", err)
	}

	for _, unit := range []string{"postfix", "dovecot"} {
		if output, err := run("systemctl", "enable", "--now", unit); err != nil {
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
		command, cancelCommand10 := commandContext(longTimeout, "apt-get", "install", "-y", "--no-install-recommends", "opendkim", "opendkim-tools")
		defer cancelCommand10()
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
		if output, keyErr := run("opendkim-genkey", "-b", "2048", "-D", keyDir, "-d", domain, "-s", "mail"); keyErr != nil {
			return result, fmt.Errorf("generate DKIM key: %s", tail(string(output), 800))
		}
	}
	_ = os.Chmod(privateKey, 0600)
	if output, err := run("chown", "-R", "opendkim:opendkim", keyDir); err != nil {
		return result, fmt.Errorf("protect DKIM keys: %s", tail(string(output), 500))
	}
	socketDir := "/var/spool/postfix/opendkim"
	if err := os.MkdirAll(socketDir, 0750); err != nil {
		return result, err
	}
	if output, err := run("chown", "opendkim:postfix", socketDir); err != nil {
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
		if output, setErr := run("postconf", "-e", setting); setErr != nil {
			_ = atomicWrite("/etc/postfix/main.cf", mainCF, 0644)
			return result, fmt.Errorf("configure Postfix DKIM: %s", tail(string(output), 500))
		}
	}
	rollback := func() {
		_ = atomicWrite("/etc/postfix/main.cf", mainCF, 0644)
		_, _ = run("systemctl", "restart", "postfix")
	}
	if output, err := run("opendkim", "-n", "-x", "/etc/opendkim.conf"); err != nil {
		rollback()
		return result, fmt.Errorf("validate OpenDKIM: %s", tail(string(output), 800))
	}
	if output, err := run("postfix", "check"); err != nil {
		rollback()
		return result, fmt.Errorf("validate Postfix: %s", tail(string(output), 800))
	}
	if output, err := run("systemctl", "enable", "--now", "opendkim"); err != nil {
		rollback()
		return result, fmt.Errorf("start OpenDKIM: %s", tail(string(output), 800))
	}
	if output, err := runLong("systemctl", "restart", "postfix"); err != nil {
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
	if output, err := run("nginx", "-t"); err != nil {
		return result, fmt.Errorf("validate mail challenge: %s", tail(string(output), 800))
	}
	if err := mustRun("systemctl", "reload", "nginx"); err != nil {
		return result, err
	}
	arguments := []string{"certonly", "--webroot", "--webroot-path", challengeRoot, "--non-interactive", "--agree-tos", "--keep-until-expiring", "--email", email, "--domain", hostname}
	if output, err := runLong("certbot", arguments...); err != nil {
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
		_, _ = run("systemctl", "restart", "postfix")
		_, _ = run("systemctl", "restart", "dovecot")
	}
	for _, setting := range []string{"myhostname=" + hostname, "mydomain=" + domain, "myorigin=$mydomain", "smtpd_tls_cert_file=" + certificate, "smtpd_tls_key_file=" + privateKey, "smtpd_tls_security_level=may", "smtp_tls_security_level=may", "smtpd_tls_auth_only=yes"} {
		if output, setErr := run("postconf", "-e", setting); setErr != nil {
			rollback()
			return result, fmt.Errorf("configure Postfix TLS: %s", tail(string(output), 800))
		}
	}
	versionOutput, _ := runOutputWithTimeout(defaultTimeout, "dovecot", "--version")
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
	if output, err := run("postfix", "check"); err != nil {
		rollback()
		return result, fmt.Errorf("validate Postfix TLS: %s", tail(string(output), 800))
	}
	if output, err := run("doveconf", "-n"); err != nil {
		rollback()
		return result, fmt.Errorf("validate Dovecot TLS: %s", tail(string(output), 1000))
	}
	if output, err := runLong("systemctl", "restart", "postfix"); err != nil {
		rollback()
		return result, fmt.Errorf("restart Postfix: %s", tail(string(output), 800))
	}
	if output, err := runLong("systemctl", "restart", "dovecot"); err != nil {
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
	addressRecordType := "AAAA"
	if parsed := net.ParseIP(publicIP); parsed != nil && parsed.To4() != nil {
		addressRecordType = "A"
	}
	addresses, _ := net.LookupIP(hostname)
	addressPresent := false
	for _, address := range addresses {
		if address.String() == publicIP {
			addressPresent = true
		}
	}
	result.Records = append(result.Records, dnsRequirement{Type: addressRecordType, Name: hostname, Value: publicIP, Present: addressPresent, Note: "Must be DNS-only, not proxied"})
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
	output, _ := runOutputWithTimeout(defaultTimeout, "apt-cache", "policy", name)
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
	// Called for every service on every refresh, so it takes the short deadline.
	_, err := runQuick("systemctl", "is-active", "--quiet", name)
	return err == nil
}

// softwareCatalogPackageNames lists every package the catalogue can display,
// so an update check can price them all in a single apt-cache call.
func softwareCatalogPackageNames() []string {
	names := []string{"docker-ce"}
	catalog, err := listSoftware()
	if err != nil {
		return names
	}
	for index := range catalog {
		names = append(names, catalog[index].Package)
	}
	return names
}

func listSoftware() ([]softwarePackage, error) {
	dockerPackage := "docker.io"
	dockerDescription := "Ubuntu-maintained container runtime"
	// Whether Docker's own repository is available was previously answered with
	// an apt-cache call on every refresh. The cached candidate list answers it
	// for free; before the first update check we simply show the Ubuntu package.
	if readCandidateCache()["docker-ce"] != "" {
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
	// Installed versions come from dpkg, which is local and cheap. Candidate
	// versions would need apt, which loads its whole cache (~77 MB peak on a
	// small instance), so they are read from the cache written by the last
	// explicit update check. Nothing here may trigger apt: this runs on every
	// refresh, and doing so is what previously exhausted memory on 1 GB hosts.
	names := make([]string, 0, len(catalog))
	for index := range catalog {
		names = append(names, catalog[index].Package)
	}
	versions := packageVersions(names)
	candidates := readCandidateCache()

	for index := range catalog {
		catalog[index].Version = versions[catalog[index].Package]
		catalog[index].Installed = catalog[index].Version != ""
		catalog[index].Candidate = candidates[catalog[index].Package]
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
	deduplicated := make([]packageSource, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%t", value.File, value.URI, value.Suite, value.SignedBy, value.Enabled)
		if seen[key] {
			continue
		}
		seen[key] = true
		deduplicated = append(deduplicated, value)
	}
	values = deduplicated
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
	official := strings.Contains(uri, "archive.ubuntu.com") || strings.Contains(uri, "security.ubuntu.com") || strings.Contains(uri, "ports.ubuntu.com") || strings.Contains(uri, "archive.canonical.com")
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
	// Offered unless the release is known to be past support. An allowlist of
	// codenames was blocking every release newer than the ones it named, which is
	// backwards: a newer Ubuntu is more likely to be carried by these
	// repositories, not less. If one genuinely has no packages for a release,
	// enabling it fails and is rolled back — a far better outcome than refusing
	// to try on a release that works.
	dockerSupported := !isEndOfLifeUbuntu(codename)
	dockerReason := ""
	if !dockerSupported {
		dockerReason = "This Ubuntu release is past its support window, so Docker no longer publishes packages for it."
	}
	return []sourceCatalogItem{
		{ID: "docker", Name: "Docker official", Description: "Docker Engine, Compose, Buildx, and containerd packages", Supported: dockerSupported, Enabled: hasURI("download.docker.com/linux/ubuntu"), Reason: dockerReason},
	}, nil
}

func enablePackageSource(id string) ([]sourceCatalogItem, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("source-enable must run as root")
	}
	codename := ubuntuCodename()
	if output, err := runLong("apt-get", "-o", "DPkg::Lock::Timeout=30", "update"); err != nil {
		return nil, fmt.Errorf("refresh package information: %s", tail(string(output), 800))
	}
	if output, err := runLong("apt-get", "-o", "DPkg::Lock::Timeout=30", "install", "-y", "--no-install-recommends", "ca-certificates", "gnupg"); err != nil {
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
	case "docker":
		allowed := repositoryPublishesSuite(curatedSourceBaseURLs["docker"], codename)
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
		architectureData, architectureErr := runOutputWithTimeout(defaultTimeout, "dpkg", "--print-architecture")
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
	if output, err := runLong("apt-get", "-o", "DPkg::Lock::Timeout=30", "update"); err != nil {
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
	if output, err := runLong("apt-get", "-o", "DPkg::Lock::Timeout=30", "update"); err != nil {
		_ = writeAudit("software.install.failed", false, id+": "+tail(string(output), 800))
		return nil, fmt.Errorf("refresh package information: %s", tail(string(output), 800))
	}
	arguments := append([]string{"install", "-y", "--no-install-recommends"}, selection.packages...)
	if output, err := runLong("apt-get", append([]string{"-o", "DPkg::Lock::Timeout=30"}, arguments...)...); err != nil {
		_ = writeAudit("software.install.failed", false, id+": "+tail(string(output), 800))
		return nil, fmt.Errorf("install %s: %s", id, tail(string(output), 800))
	}
	if selection.unit != "" {
		if output, err := run("systemctl", "enable", "--now", selection.unit); err != nil {
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
			if itemServer == "" {
				itemServer = "nginx"
			}
			if itemServer == webServer {
				plan.Affected = append(plan.Affected, item.Domain)
			}
		}
	case "nodejs":
		for _, item := range sites {
			if item.Kind == "node" {
				plan.Affected = append(plan.Affected, item.Domain)
			}
		}
	case "mariadb", "mysql", "postgresql":
		engine := map[string]string{"mariadb": "MariaDB", "mysql": "MySQL", "postgresql": "PostgreSQL"}[id]
		for _, item := range databases {
			itemEngine := item.Engine
			if itemEngine == "" {
				itemEngine = "MariaDB"
			}
			if itemEngine == engine {
				plan.Affected = append(plan.Affected, item.Name)
			}
		}
	case "docker":
		inventory, _ := inspectContainers()
		for _, item := range inventory.Containers {
			plan.Affected = append(plan.Affected, item.Name)
		}
	case "certbot":
		statuses, _ := listTLS()
		for _, item := range statuses {
			if item.Certificate {
				plan.Affected = append(plan.Affected, item.Domain)
			}
		}
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
	if err != nil {
		return nil, err
	}
	if !plan.Allowed {
		return nil, errors.New(plan.Reason)
	}
	packages := map[string][]string{
		"nginx": {"nginx"}, "apache2": {"apache2"}, "mariadb": {"mariadb-server"}, "mysql": {"mysql-server"},
		"postgresql": {"postgresql"}, "redis": {"redis-server"}, "nodejs": {"nodejs", "npm"}, "vsftpd": {"vsftpd"},
		"docker":   {"docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"},
		"fail2ban": {"fail2ban"}, "certbot": {"certbot"}, "git": {"git"},
	}
	selection, ok := packages[id]
	if !ok {
		return nil, errors.New("this software must be managed from its dedicated section")
	}
	if id == "docker" && packageVersion("docker-ce") == "" {
		selection = []string{"docker.io"}
	}
	_ = writeAudit("software.remove.started", true, id)
	arguments := append([]string{"remove", "-y"}, selection...)
	if output, err := runLong("apt-get", append([]string{"-o", "DPkg::Lock::Timeout=30"}, arguments...)...); err != nil {
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
	catalog := []struct{ version, support string }{
		{"7.4", "End of life"},
		{"8.0", "End of life"},
		{"8.1", "End of life"},
		{"8.2", "Security fixes"},
		{"8.3", "Security fixes"},
		{"8.4", "Active support"},
		{"8.5", "Active support"},
	}
	for _, entry := range catalog {
		version := entry.version
		base := "php" + version
		installed := packageVersion(base+"-fpm") != ""
		available := packageCandidate(base+"-fpm") != ""
		if entry.support == "End of life" && !installed {
			continue
		}
		value := phpVersionStatus{Version: version, Installed: installed, Available: available, Active: unitActive(base + "-fpm"), Extensions: []string{}, UsedBy: []string{}, Support: entry.support}
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
	output, err := runLong("apt-get", append([]string{"-o", "DPkg::Lock::Timeout=30"}, arguments...)...)
	if err != nil {
		return nil, fmt.Errorf("install PHP %s: %s", version, tail(string(output), 1200))
	}
	if err := mustRun("systemctl", "enable", "--now", base+"-fpm"); err != nil {
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
	output, err := runLong("apt-get", append([]string{"-o", "DPkg::Lock::Timeout=30"}, arguments...)...)
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
	output, err := run("apt-get", "-o", "DPkg::Lock::Timeout=30", action, "-y", "--no-install-recommends", packageName)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %s", action, packageName, tail(string(output), 1200))
	}
	if err := mustRun("systemctl", "restart", base+"-fpm"); err != nil {
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
	if output, err := runOutputWithTimeout(defaultTimeout, "node", "--version"); err == nil {
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
		_, _ = run("systemctl", "reload", map[string]string{"nginx": "nginx", "apache": "apache2"}[webServer])
	}
	validation, cancelValidation := commandContext(defaultTimeout, "nginx", "-t")
	defer cancelValidation()
	if webServer == "apache" {
		validation2, cancelValidation2 := commandContext(defaultTimeout, "apache2ctl", "configtest")
		validation = validation2
		defer cancelValidation2()
	}
	if output, err := validation.CombinedOutput(); err != nil {
		rollback()
		return value, fmt.Errorf("%s validation failed: %s", webServer, tail(string(output), 800))
	}
	if err := mustRun("systemctl", "reload", map[string]string{"nginx": "nginx", "apache": "apache2"}[webServer]); err != nil {
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
	if output, err := runLong("apt-get", "-o", "DPkg::Lock::Timeout=30", "install", "-y", "--no-install-recommends", "nodejs", "npm"); err != nil {
		return nil, fmt.Errorf("Node.js installation failed: %s", tail(string(output), 800))
	}
	version, _ := runOutputWithTimeout(defaultTimeout, "node", "--version")
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
	if err := mustRun("useradd", "--system", "--home", root, "--shell", "/usr/sbin/nologin", user); err != nil {
		return value, fmt.Errorf("create service user: %w", err)
	}
	serverJS := fmt.Sprintf("const http=require('http');const port=process.env.PORT||%d;http.createServer((req,res)=>res.end('<h1>%s</h1><p>Node.js managed by ServerDeck.</p>')).listen(port,'127.0.0.1');\n", port, domain)
	if err := os.WriteFile(filepath.Join(root, "server.js"), []byte(serverJS), 0640); err != nil {
		return value, err
	}
	_, _ = run("chown", "-R", user+":"+user, filepath.Dir(root))
	versionOutput, _ := runOutputWithTimeout(defaultTimeout, "node", "--version")
	nodeVersion := strings.TrimPrefix(strings.TrimSpace(string(versionOutput)), "v")
	unit := fmt.Sprintf("[Unit]\nDescription=ServerDeck Node project %s\nAfter=network.target\n\n[Service]\nUser=%s\nGroup=%s\nWorkingDirectory=%s\nEnvironment=PORT=%d\nExecStart=/usr/bin/node server.js\nRestart=on-failure\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nReadWritePaths=%s\n\n[Install]\nWantedBy=multi-user.target\n", domain, user, user, root, port, root)
	unitPath := filepath.Join("/etc/systemd/system", serviceName+".service")
	if err := atomicWrite(unitPath, []byte(unit), 0644); err != nil {
		return value, err
	}
	config := fmt.Sprintf("server {\n listen 80;\n listen [::]:80;\n server_name %s;\n location / {\n  proxy_pass http://127.0.0.1:%d;\n  proxy_set_header Host $host;\n  proxy_set_header X-Real-IP $remote_addr;\n  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n  proxy_set_header X-Forwarded-Proto $scheme;\n }\n}\n", domain, port)
	configPath, enabledPath := filepath.Join("/etc/nginx/sites-available", domain), filepath.Join("/etc/nginx/sites-enabled", domain)
	if webServer == "apache" {
		if output, err := run("a2enmod", "proxy", "proxy_http", "headers"); err != nil {
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
	} else if output, err := run("a2ensite", domain+".conf"); err != nil {
		return value, fmt.Errorf("enable Apache site: %s", tail(string(output), 800))
	}
	_, _ = run("systemctl", "daemon-reload")
	if output, err := run("systemctl", "enable", "--now", serviceName); err != nil {
		return value, fmt.Errorf("start project: %s", tail(string(output), 800))
	}
	validation, cancelValidation3 := commandContext(defaultTimeout, "nginx", "-t")
	defer cancelValidation3()
	if webServer == "apache" {
		validation2, cancelValidation4 := commandContext(defaultTimeout, "apache2ctl", "configtest")
		validation = validation2
		defer cancelValidation4()
	}
	if output, err := validation.CombinedOutput(); err != nil {
		return value, fmt.Errorf("%s validation failed: %s", webServer, tail(string(output), 800))
	}
	if err := mustRun("systemctl", "reload", map[string]string{"nginx": "nginx", "apache": "apache2"}[webServer]); err != nil {
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

// createSite builds a site with the default canonical host preference.
func createSite(domain, kind string) (site, error) {
	return createSiteWithCanonical(domain, kind, canonicalNonWWW)
}

// createSiteWithDatabase creates a site and, optionally, a database bound to it.
//
// Creating the two together is what makes the association reliable. A database
// made separately has nothing tying it to a site, so backups cannot know to
// include it — the site gets archived as files only, which cannot restore it.
func createSiteWithDatabase(domain, kind string, canonical canonicalHost, withDatabase bool) (site, error) {
	value, err := createSiteWithCanonical(domain, kind, canonical)
	if err != nil || !withDatabase {
		return value, err
	}

	name := databaseNameForDomain(domain)
	user := name
	if len(user) > 32 {
		user = user[:32]
	}
	created, err := createDatabase(name, user)
	if err != nil {
		// The site is left in place: it is serving, and tearing it down because
		// a database could not be made would be the more destructive answer. The
		// caller reports the failure so the user can add one afterwards.
		return value, fmt.Errorf("the website was created, but its database was not: %w", err)
	}

	value.Database = created.Name
	value.DatabaseUser = created.Username
	if err := writeSiteMetadata(value); err != nil {
		return value, fmt.Errorf("the website and database were created, but the link between them was not saved: %w", err)
	}
	// Returned once, like every other generated credential, because the stored
	// record deliberately never keeps it.
	value.DatabasePassword = created.Password
	return value, nil
}

func createSiteWithCanonical(domain, kind string, canonical canonicalHost) (site, error) {
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
			if output, err := run("a2enmod", "proxy_fcgi", "setenvif", "rewrite"); err != nil {
				return value, fmt.Errorf("enable Apache PHP modules: %s", tail(string(output), 800))
			}
			phpBlock = fmt.Sprintf("    <FilesMatch \"\\.php$\">\n        SetHandler \"proxy:unix:%s|fcgi://localhost/\"\n    </FilesMatch>\n", socket)
		}
	}

	config := ""
	if webServer == "nginx" {
		fallback := "/index.html"
		if kind == "php" {
			// Route unmatched paths through the front controller so PHP
			// applications with pretty URLs work without manual edits.
			fallback = "/index.php?$args"
		}
		// A www alias belongs on a registrable domain only; see domains.go.
		// When there is one, it gets its own server block that redirects to the
		// canonical host, so the two names never serve duplicate content.
		redirectBlock := ""
		serving := serverNames(domain)
		if from, to, ok := canonicalRedirect(domain, canonical); ok {
			redirectBlock = fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    return 301 $scheme://%s$request_uri;
}

`, from, to)
			serving = []string{to}
		}
		config = redirectBlock + fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    root %s;
    index index.html;

%s
    location / {
        try_files $uri $uri/ %s;
    }
%s}
`, strings.Join(serving, " "), root, nginxSecurityHeaders, fallback, phpBlock)
	} else {
		// Apache keeps the primary name and its aliases separate, so the alias
		// line is omitted entirely rather than left empty.
		aliasLine := ""
		if alias, ok := wwwAliasFor(domain); ok {
			aliasLine = fmt.Sprintf("    ServerAlias %s\n", alias)
		}
		primary := normaliseHost(domain)
		redirectBlock := ""
		if from, to, ok := canonicalRedirect(domain, canonical); ok {
			// The non-canonical name becomes its own vhost that redirects, so the
			// serving vhost answers on exactly one host.
			redirectBlock = fmt.Sprintf("<VirtualHost *:80>\n    ServerName %s\n    Redirect permanent / http://%s/\n</VirtualHost>\n\n", from, to)
			primary = to
			aliasLine = ""
		}
		config = redirectBlock + fmt.Sprintf(`<VirtualHost *:80>
    ServerName %s
%s    DocumentRoot %s
    <Directory %s>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
        DirectoryIndex index.php index.html
    </Directory>
%s</VirtualHost>
`, primary, aliasLine, root, root, phpBlock)
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
	} else if output, err := run("a2ensite", domain+".conf"); err != nil {
		_ = os.Remove(configPath)
		return value, fmt.Errorf("enable Apache site: %s", tail(string(output), 800))
	}
	validation, cancelValidation5 := commandContext(defaultTimeout, "nginx", "-t")
	defer cancelValidation5()
	if webServer == "apache" {
		validation2, cancelValidation6 := commandContext(defaultTimeout, "apache2ctl", "configtest")
		validation = validation2
		defer cancelValidation6()
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
	if output, err := runLong("systemctl", "reload", map[string]string{"nginx": "nginx", "apache": "apache2"}[webServer]); err != nil {
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
	if err != nil {
		return plan, err
	}
	sources := map[string]bool{}
	for _, item := range sites {
		source := item.WebServer
		if source == "" {
			source = "nginx"
		}
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
	for source := range sources {
		plan.Source = source
	}
	if plan.Source == target {
		plan.Allowed = false
		plan.Reason = "Managed websites already use " + target
		return plan, nil
	}
	plan.Reason = fmt.Sprintf("Migrate %d managed website(s), including %d TLS site(s)", len(plan.Sites), len(plan.TLS))
	return plan, nil
}

func migrateWebServer(target string) (webMigrationPlan, error) {
	if os.Geteuid() != 0 {
		return webMigrationPlan{}, errors.New("web-migrate must run as root")
	}
	plan, err := planWebMigration(target)
	if err != nil {
		return plan, err
	}
	if !plan.Allowed {
		return plan, errors.New(plan.Reason)
	}
	safety, err := createBackup()
	if err != nil {
		return plan, fmt.Errorf("create migration safety backup: %w", err)
	}
	_ = writeAudit("web.migration.started", true, plan.Source+" -> "+target+" safety "+safety.ID)
	sourceUnit := map[string]string{"nginx": "nginx", "apache": "apache2"}[plan.Source]
	targetUnit := map[string]string{"nginx": "nginx", "apache": "apache2"}[target]
	created := []string{}
	metadataOriginals := map[string][]byte{}
	rollback := func(detail string) {
		_, _ = run("systemctl", "stop", targetUnit)
		for _, path := range created {
			_ = os.Remove(path)
		}
		for path, contents := range metadataOriginals {
			_ = atomicWrite(path, contents, 0644)
		}
		_, _ = run("systemctl", "start", sourceUnit)
		_ = writeAudit("web.migration.rolled-back", false, detail+" safety "+safety.ID)
	}
	if err := mustRun("systemctl", "stop", sourceUnit); err != nil {
		return plan, fmt.Errorf("stop %s before migration: %w", plan.Source, err)
	}
	packages := []string{"nginx", "certbot", "python3-certbot-nginx"}
	if target == "apache" {
		packages = []string{"apache2", "certbot", "python3-certbot-apache"}
	}
	arguments := append([]string{"install", "-y", "--no-install-recommends"}, packages...)
	if output, installErr := runLong("apt-get", append([]string{"-o", "DPkg::Lock::Timeout=30"}, arguments...)...); installErr != nil {
		rollback("install target: " + tail(string(output), 800))
		return plan, fmt.Errorf("install %s: %s", target, tail(string(output), 800))
	}
	if target == "apache" {
		if output, moduleErr := run("a2enmod", "proxy", "proxy_http", "proxy_fcgi", "setenvif", "rewrite", "headers", "ssl"); moduleErr != nil {
			rollback("enable Apache modules: " + tail(string(output), 800))
			return plan, fmt.Errorf("enable Apache modules: %s", tail(string(output), 800))
		}
	}
	sites, _ := listSites()
	for _, item := range sites {
		config, renderErr := renderSiteForWebServer(item, target)
		if renderErr != nil {
			rollback(renderErr.Error())
			return plan, renderErr
		}
		configPath := filepath.Join("/etc/nginx/sites-available", item.Domain)
		enabledPath := filepath.Join("/etc/nginx/sites-enabled", item.Domain)
		if target == "apache" {
			configPath = filepath.Join("/etc/apache2/sites-available", item.Domain+".conf")
			enabledPath = filepath.Join("/etc/apache2/sites-enabled", item.Domain+".conf")
		}
		if _, statErr := os.Lstat(configPath); statErr == nil {
			rollback("target configuration already exists for " + item.Domain)
			return plan, errors.New("target configuration already exists for " + item.Domain)
		}
		if writeErr := atomicWrite(configPath, []byte(config), 0644); writeErr != nil {
			rollback(writeErr.Error())
			return plan, writeErr
		}
		created = append(created, configPath)
		if symlinkErr := os.Symlink(configPath, enabledPath); symlinkErr != nil {
			rollback(symlinkErr.Error())
			return plan, symlinkErr
		}
		created = append(created, enabledPath)
	}
	validation, cancelValidation7 := commandContext(defaultTimeout, "nginx", "-t")
	defer cancelValidation7()
	if target == "apache" {
		validation2, cancelValidation8 := commandContext(defaultTimeout, "apache2ctl", "configtest")
		validation = validation2
		defer cancelValidation8()
	}
	if output, validationErr := validation.CombinedOutput(); validationErr != nil {
		rollback("validation: " + tail(string(output), 1000))
		return plan, fmt.Errorf("%s validation failed: %s", target, tail(string(output), 1000))
	}
	if output, startErr := run("systemctl", "enable", "--now", targetUnit); startErr != nil {
		rollback("start target: " + tail(string(output), 800))
		return plan, fmt.Errorf("start %s: %s", target, tail(string(output), 800))
	}
	for _, item := range sites {
		item.WebServer = target
		metadataPath := filepath.Join("/var/lib/serverdeck/sites", item.Domain+".json")
		if original, readErr := os.ReadFile(metadataPath); readErr == nil {
			metadataOriginals[metadataPath] = original
		}
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
	if _, err := os.Stat(filepath.Join(certificatePath, "cert.pem")); err == nil {
		tls = true
	}
	if target == "nginx" {
		listenTLS := ""
		if tls {
			listenTLS = fmt.Sprintf("    listen 443 ssl;\n    listen [::]:443 ssl;\n    ssl_certificate %s/fullchain.pem;\n    ssl_certificate_key %s/privkey.pem;\n", certificatePath, certificatePath)
		}
		if item.Kind == "node" || item.Kind == "proxy" {
			return fmt.Sprintf("server {\n    listen 80;\n    listen [::]:80;\n%s    server_name %s;\n    location / {\n        proxy_pass http://127.0.0.1:%d;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n}\n", listenTLS, strings.Join(serverNames(item.Domain), " "), item.Port), nil
		}
		phpBlock := ""
		if item.Kind == "php" {
			socket := "/run/php/php" + item.PHPVersion + "-fpm.sock"
			if _, err := os.Stat(socket); err != nil {
				return "", errors.New("PHP-FPM socket is unavailable for " + item.Domain)
			}
			phpBlock = fmt.Sprintf("    location ~ \\.php$ {\n        include snippets/fastcgi-php.conf;\n        fastcgi_pass unix:%s;\n    }\n", socket)
		}
		fallback := "/index.html"
		if item.Kind == "php" {
			fallback = "/index.php?$args"
		}
		return fmt.Sprintf("server {\n    listen 80;\n    listen [::]:80;\n%s    server_name %s;\n    root %s;\n    index index.php index.html;\n    location / { try_files $uri $uri/ %s; }\n%s}\n", listenTLS, strings.Join(serverNames(item.Domain), " "), item.Root, fallback, phpBlock), nil
	}
	if target != "apache" {
		return "", errors.New("unsupported migration target")
	}
	body := ""
	if item.Kind == "node" || item.Kind == "proxy" {
		body = fmt.Sprintf("    ProxyPreserveHost On\n    ProxyPass / http://127.0.0.1:%d/\n    ProxyPassReverse / http://127.0.0.1:%d/\n    RequestHeader set X-Forwarded-Proto expr=%%{REQUEST_SCHEME}\n", item.Port, item.Port)
	} else {
		body = fmt.Sprintf("    DocumentRoot %s\n    <Directory %s>\n        Options FollowSymLinks\n        AllowOverride All\n        Require all granted\n        DirectoryIndex index.php index.html\n    </Directory>\n", item.Root, item.Root)
		if item.Kind == "php" {
			socket := "/run/php/php" + item.PHPVersion + "-fpm.sock"
			if _, err := os.Stat(socket); err != nil {
				return "", errors.New("PHP-FPM socket is unavailable for " + item.Domain)
			}
			body += fmt.Sprintf("    <FilesMatch \"\\.php$\">\n        SetHandler \"proxy:unix:%s|fcgi://localhost/\"\n    </FilesMatch>\n", socket)
		}
	}
	aliasLine := ""
	if alias, ok := wwwAliasFor(item.Domain); ok {
		aliasLine = fmt.Sprintf("    ServerAlias %s\n", alias)
	}
	config := fmt.Sprintf("<VirtualHost *:80>\n    ServerName %s\n%s%s</VirtualHost>\n", normaliseHost(item.Domain), aliasLine, body)
	if tls {
		config += fmt.Sprintf("<VirtualHost *:443>\n    ServerName %s\n%s    SSLEngine on\n    SSLCertificateFile %s/fullchain.pem\n    SSLCertificateKeyFile %s/privkey.pem\n%s</VirtualHost>\n", normaliseHost(item.Domain), aliasLine, certificatePath, certificatePath, body)
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
	emitProgress("preflight", "running", "Checking operating system, package manager, and existing services")
	if os.Geteuid() != 0 {
		return nil, errors.New("stack-install must run as root")
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		return nil, errors.New("apt-get is required")
	}

	webPackages := map[string][]string{
		"nginx":  {"nginx", "certbot", "python3-certbot-nginx"},
		"apache": {"apache2", "certbot", "python3-certbot-apache"},
		"none":   {},
	}
	databasePackages := map[string][]string{
		"mariadb":    {"mariadb-server"},
		"mysql":      {"mysql-server"},
		"postgresql": {"postgresql"},
		"none":       {},
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
	emitProgress("preflight", "completed", "Selections and compatibility checks passed")
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
		emitProgress("complete", "completed", "No software was selected")
		return map[string]interface{}{"installed": []string{}}, nil
	}

	if err := writeAudit("stack.install.started", true, fmt.Sprintf("web=%s database=%s php=%t node=%t redis=%t ftp=%t", webServer, database, php, node, redis, ftp)); err != nil {
		return nil, err
	}
	emitProgress("repositories", "running", "Refreshing package information from configured sources")
	if output, err := runProgressCommand("apt-get", "update"); err != nil {
		_ = writeAudit("stack.install.failed", false, tail(string(output), 800))
		emitProgress("repositories", "failed", "Package information refresh failed")
		return nil, fmt.Errorf("apt-get update failed: %s", tail(string(output), 800))
	}
	emitProgress("repositories", "completed", "Package information is current")
	arguments := append([]string{"install", "-y", "--no-install-recommends"}, packages...)
	emitProgress("packages", "running", "Installing selected hosting packages")
	if output, err := runProgressCommand("apt-get", arguments...); err != nil {
		_ = writeAudit("stack.install.failed", false, tail(string(output), 800))
		emitProgress("packages", "failed", "Package installation failed")
		return nil, fmt.Errorf("package installation failed: %s", tail(string(output), 800))
	}
	emitProgress("packages", "completed", fmt.Sprintf("Installed or verified %d packages", len(packages)))
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
		phase := "service-" + name
		emitProgress(phase, "running", "Enabling and starting "+name)
		if output, err := runProgressCommand("systemctl", "enable", "--now", name); err != nil {
			_ = writeAudit("stack.install.failed", false, tail(string(output), 800))
			emitProgress(phase, "failed", "Could not start "+name)
			return nil, fmt.Errorf("enable %s: %s", name, tail(string(output), 800))
		}
		emitProgress(phase, "completed", name+" is running")
	}
	if fail2ban {
		emitProgress("security", "running", "Configuring Fail2ban protection for SSH")
		configuration := "[sshd]\nenabled = true\nbackend = systemd\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n"
		if err := atomicWrite("/etc/fail2ban/jail.d/serverdeck.local", []byte(configuration), 0644); err != nil {
			return nil, err
		}
		if output, err := run("systemctl", "enable", "--now", "fail2ban"); err != nil {
			emitProgress("security", "failed", "Could not enable Fail2ban")
			return nil, fmt.Errorf("enable Fail2ban: %s", tail(string(output), 800))
		}
		emitProgress("security", "completed", "Fail2ban SSH protection is active")
	}
	if firewall {
		emitProgress("firewall", "running", fmt.Sprintf("Allowing SSH port %d, HTTP, and HTTPS before enabling UFW", sshPort))
		if _, err := enableFirewall(sshPort); err != nil {
			emitProgress("firewall", "failed", "Firewall configuration failed")
			return nil, err
		}
		emitProgress("firewall", "completed", "Firewall is active with SSH and web traffic allowed")
	}
	if err := writeAudit("stack.install.completed", true, "web stack installation completed"); err != nil {
		return nil, err
	}
	emitProgress("complete", "completed", "Server preparation completed successfully")
	return map[string]interface{}{"installed": packages, "web_server": webServer, "database": database, "fail2ban": fail2ban, "firewall": firewall}, nil
}

func emitProgress(phase, status, message string) {
	message = strings.ReplaceAll(strings.ReplaceAll(message, "\n", " "), "|", "/")
	fmt.Fprintf(os.Stderr, "SERVERDECK_PROGRESS|%s|%s|%s\n", phase, status, message)
}

func runProgressCommand(name string, arguments ...string) ([]byte, error) {
	command, cancelCommand11 := commandContext(defaultTimeout, name, arguments...)
	defer cancelCommand11()
	var output bytes.Buffer
	writer := io.MultiWriter(os.Stderr, &output)
	command.Stdout = writer
	command.Stderr = writer
	err := command.Run()
	return output.Bytes(), err
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

type appCatalogEntry struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Website     string   `json:"website"`
	Database    string   `json:"database"`
	Extensions  []string `json:"extensions,omitempty"`
	Supported   bool     `json:"supported"`
	Reason      string   `json:"reason,omitempty"`
	Installed   []string `json:"installed,omitempty"`
	Notes       string   `json:"notes,omitempty"`
}

type appCatalogReport struct {
	WebServer  string            `json:"web_server,omitempty"`
	PHPVersion string            `json:"php_version,omitempty"`
	Engines    []string          `json:"engines"`
	Apps       []appCatalogEntry `json:"apps"`
}

type installedApp struct {
	App          string `json:"app"`
	Name         string `json:"name"`
	Domain       string `json:"domain"`
	Version      string `json:"version,omitempty"`
	Database     string `json:"database,omitempty"`
	DatabaseUser string `json:"database_user,omitempty"`
	InstalledAt  string `json:"installed_at"`
}

type appInstallResult struct {
	App      string    `json:"app"`
	Name     string    `json:"name"`
	Domain   string    `json:"domain"`
	URL      string    `json:"url"`
	Version  string    `json:"version,omitempty"`
	Database *database `json:"database,omitempty"`
	Notes    string    `json:"notes"`
}

type appDownload struct {
	url            string
	checksumURL    string
	expectedSHA256 string
	githubRepo     string
	assetPattern   string
	format         string
}

type appDefinition struct {
	id             string
	name           string
	category       string
	description    string
	website        string
	database       string
	extensions     []string
	download       appDownload
	archiveSubPath string
	notes          string
	configure      func(siteRoot, domain string, db *database) error
}

// appDefinitions is the reviewed one-click catalog. Download URLs must stay
// on the project's official domain (or its official GitHub releases); never
// add mirrors or unreviewed sources.
func appDefinitions() []appDefinition {
	return []appDefinition{
		{
			id: "wordpress", name: "WordPress", category: "CMS and blogging",
			description: "The world's most widely used content management system for blogs and websites.",
			website:     "https://wordpress.org",
			database:    "mysql",
			extensions:  []string{"mysql", "curl", "gd", "intl", "mbstring", "xml", "zip"},
			download:    appDownload{url: "https://wordpress.org/wordpress-7.0.2.tar.gz", expectedSHA256: "d4a4d219dea64c6c68e62f2ffc3f331c5475510246d6c44f61fb52f377d295b9", format: "tar.gz"},
			notes:       "The database connection is pre-configured. Open the site to choose a language and create the administrator account.",
			configure:   configureWordPress,
		},
		{
			id: "drupal", name: "Drupal", category: "CMS and blogging",
			description: "A flexible CMS for structured content and larger editorial sites.",
			website:     "https://www.drupal.org",
			database:    "any",
			extensions:  []string{"mysql", "curl", "gd", "mbstring", "xml", "zip"},
			download:    appDownload{url: "https://www.drupal.org/download-latest/tar.gz", format: "tar.gz"},
			notes:       "Open the site and finish the Drupal installer with the database credentials shown after installation.",
		},
		{
			id: "joomla", name: "Joomla", category: "CMS and blogging",
			description: "A mature CMS with strong template and extension ecosystems.",
			website:     "https://www.joomla.org",
			database:    "mysql",
			extensions:  []string{"mysql", "curl", "gd", "intl", "mbstring", "xml", "zip"},
			download:    appDownload{githubRepo: "joomla/joomla-cms", assetPattern: `^Joomla_.*-Stable-Full_Package\.tar\.gz$`, format: "tar.gz"},
			notes:       "Open the site and finish the Joomla installer with the database credentials shown after installation.",
		},
		{
			id: "grav", name: "Grav", category: "CMS and blogging",
			description: "A fast flat-file CMS with an admin panel and no database requirement.",
			website:     "https://getgrav.org",
			database:    "none",
			extensions:  []string{"curl", "gd", "intl", "mbstring", "xml", "zip"},
			download:    appDownload{url: "https://getgrav.org/download/core/grav-admin/latest", format: "zip"},
			notes:       "Open the site to create the Grav admin account.",
		},
		{
			id: "nextcloud", name: "Nextcloud", category: "Collaboration",
			description:    "Self-hosted file sync, sharing, calendars, and collaboration.",
			website:        "https://nextcloud.com",
			database:       "any",
			extensions:     []string{"mysql", "curl", "gd", "intl", "mbstring", "xml", "zip", "bcmath"},
			download:       appDownload{url: "https://download.nextcloud.com/server/releases/latest.tar.bz2", checksumURL: "https://download.nextcloud.com/server/releases/latest.tar.bz2.sha256", format: "tar.bz2"},
			archiveSubPath: "",
			notes:          "Open the site and finish the Nextcloud installer with the database credentials shown after installation.",
		},
		{
			id: "roundcube", name: "Roundcube", category: "Collaboration",
			description: "A browser-based IMAP email client.",
			website:     "https://roundcube.net",
			database:    "mysql",
			extensions:  []string{"mysql", "curl", "gd", "intl", "mbstring", "xml", "zip"},
			download:    appDownload{githubRepo: "roundcube/roundcubemail", assetPattern: `^roundcubemail-[0-9.]+-complete\.tar\.gz$`, format: "tar.gz"},
			notes:       "Open /installer on the site to finish setup with the database credentials, then disable the installer as instructed.",
		},
		{
			id: "mediawiki", name: "MediaWiki", category: "Knowledge",
			description: "The wiki engine that powers Wikipedia. Long-term support release.",
			website:     "https://www.mediawiki.org",
			database:    "any",
			extensions:  []string{"mysql", "curl", "intl", "mbstring", "xml"},
			download:    appDownload{url: "https://releases.wikimedia.org/mediawiki/1.43/mediawiki-1.43.9.tar.gz", format: "tar.gz"},
			notes:       "Open the site and finish the MediaWiki installer with the database credentials shown after installation.",
		},
		{
			id: "phpmyadmin", name: "phpMyAdmin", category: "Administration",
			description: "Web administration for the MariaDB or MySQL server on this machine.",
			website:     "https://www.phpmyadmin.net",
			database:    "none",
			extensions:  []string{"mysql", "mbstring", "xml", "zip"},
			download:    appDownload{url: "https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz", checksumURL: "https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz.sha256", format: "tar.gz"},
			notes:       "Sign in with an existing database account. ServerDeck database credentials work here.",
			configure:   configurePHPMyAdmin,
		},
		{
			id: "matomo", name: "Matomo", category: "Analytics",
			description:    "Privacy-focused, self-hosted web analytics.",
			website:        "https://matomo.org",
			database:       "mysql",
			extensions:     []string{"mysql", "curl", "gd", "mbstring", "xml", "zip"},
			download:       appDownload{url: "https://builds.matomo.org/matomo-5.12.0.tar.gz", expectedSHA256: "ca24145dbf721a027c3c538bd6dc97b57126802be26aa0ad3740f0c4a706655d", format: "tar.gz"},
			archiveSubPath: "matomo",
			notes:          "Open the site and finish the Matomo installer with the database credentials shown after installation.",
		},
		{
			id: "opencart", name: "OpenCart", category: "E-commerce",
			description:    "A lightweight open-source online store.",
			website:        "https://www.opencart.com",
			database:       "mysql",
			extensions:     []string{"mysql", "curl", "gd", "mbstring", "xml", "zip"},
			download:       appDownload{githubRepo: "opencart/opencart", assetPattern: `^opencart-[0-9.]+\.zip$`, format: "zip"},
			archiveSubPath: "upload",
			notes:          "Open the site and finish the OpenCart installer with the database credentials shown after installation.",
			configure:      configureOpenCart,
		},
		{
			id: "prestashop", name: "PrestaShop", category: "E-commerce",
			description: "A feature-rich open-source e-commerce platform.",
			website:     "https://prestashop-project.org",
			database:    "mysql",
			extensions:  []string{"mysql", "curl", "gd", "intl", "mbstring", "xml", "zip", "bcmath", "soap"},
			download:    appDownload{githubRepo: "PrestaShop/PrestaShop", assetPattern: `^prestashop_[0-9.]+\.zip$`, format: "zip"},
			notes:       "Open the site to unpack and run the PrestaShop installer with the database credentials shown after installation.",
		},
		{
			id: "dolibarr", name: "Dolibarr", category: "Business",
			description:    "Open-source ERP and CRM for small organizations.",
			website:        "https://www.dolibarr.org",
			database:       "mysql",
			extensions:     []string{"mysql", "curl", "gd", "intl", "mbstring", "xml", "zip"},
			download:       appDownload{githubRepo: "Dolibarr/dolibarr", assetPattern: `^dolibarr-[0-9.]+\.tgz$`, format: "tar.gz"},
			archiveSubPath: "htdocs",
			notes:          "Open the site and finish the Dolibarr installer with the database credentials shown after installation. Documents are stored outside the web root.",
			configure:      configureDolibarr,
		},
	}
}

func findAppDefinition(id string) (appDefinition, error) {
	for _, definition := range appDefinitions() {
		if definition.id == id {
			return definition, nil
		}
	}
	return appDefinition{}, errors.New("unknown application ID")
}

func appDownloadVerifiable(definition appDefinition) bool {
	return definition.download.checksumURL != "" || definition.download.expectedSHA256 != "" || definition.download.githubRepo != ""
}

func detectActiveWebServer() string {
	if packageVersion("nginx") != "" && unitActive("nginx") {
		return "nginx"
	}
	if packageVersion("apache2") != "" && unitActive("apache2") {
		return "apache"
	}
	return ""
}

func detectDatabaseEngines() []string {
	engines := []string{}
	if packageVersion("mariadb-server") != "" {
		engines = append(engines, "MariaDB")
	}
	if packageVersion("mysql-server") != "" {
		engines = append(engines, "MySQL")
	}
	if packageVersion("postgresql") != "" {
		engines = append(engines, "PostgreSQL")
	}
	return engines
}

func hasMySQLFamilyEngine(engines []string) bool {
	for _, engine := range engines {
		if engine == "MariaDB" || engine == "MySQL" {
			return true
		}
	}
	return false
}

func newestPHPVersion() string {
	sockets, _ := filepath.Glob("/run/php/php[0-9]*-fpm.sock")
	if len(sockets) == 0 {
		return ""
	}
	sort.Strings(sockets)
	return strings.TrimSuffix(strings.TrimPrefix(filepath.Base(sockets[len(sockets)-1]), "php"), "-fpm.sock")
}

func appCatalog() (appCatalogReport, error) {
	report := appCatalogReport{
		WebServer:  detectActiveWebServer(),
		PHPVersion: newestPHPVersion(),
		Engines:    detectDatabaseEngines(),
		Apps:       []appCatalogEntry{},
	}
	installed, err := listInstalledApps()
	if err != nil {
		return report, err
	}
	installedDomains := map[string][]string{}
	for _, record := range installed {
		installedDomains[record.App] = append(installedDomains[record.App], record.Domain)
	}
	for _, definition := range appDefinitions() {
		entry := appCatalogEntry{
			ID:          definition.id,
			Name:        definition.name,
			Category:    definition.category,
			Description: definition.description,
			Website:     definition.website,
			Database:    definition.database,
			Extensions:  definition.extensions,
			Supported:   true,
			Installed:   installedDomains[definition.id],
			Notes:       definition.notes,
		}
		switch {
		case report.WebServer == "":
			entry.Supported = false
			entry.Reason = "Nginx or Apache must be installed and running"
		case report.PHPVersion == "":
			entry.Supported = false
			entry.Reason = "PHP-FPM must be installed"
		case definition.database == "mysql" && !hasMySQLFamilyEngine(report.Engines):
			entry.Supported = false
			entry.Reason = "MariaDB or MySQL must be installed"
		case definition.database == "any" && len(report.Engines) == 0:
			entry.Supported = false
			entry.Reason = "A managed database server must be installed"
		case !appDownloadVerifiable(definition):
			entry.Supported = false
			entry.Reason = "The publisher does not provide a checksum ServerDeck can verify"
		}
		report.Apps = append(report.Apps, entry)
	}
	return report, nil
}

func listInstalledApps() ([]installedApp, error) {
	paths, err := filepath.Glob("/var/lib/serverdeck/apps/*.json")
	if err != nil {
		return nil, err
	}
	values := make([]installedApp, 0, len(paths))
	for _, path := range paths {
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		var value installedApp
		if err := json.Unmarshal(contents, &value); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Domain < values[j].Domain })
	return values, nil
}

// databaseIdentifier derives a managed database/user name from the app and
// domain, constrained to databaseNamePattern and MySQL's 32-character user
// limit.
func databaseIdentifier(appID, domain string) string {
	cleaned := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, strings.ToLower(domain))
	name := appID + "_" + cleaned
	if len(name) > 32 {
		name = name[:32]
	}
	return strings.TrimRight(name, "_")
}

func resolveGitHubDownload(repo, pattern string) (string, string, string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	request, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", "", "", err
	}
	request.Header.Set("User-Agent", "ServerDeck-Agent/"+version)
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := client.Do(request)
	if err != nil {
		return "", "", "", fmt.Errorf("query latest release: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("query latest release: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024))
	if err != nil {
		return "", "", "", err
	}
	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Digest             string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return "", "", "", fmt.Errorf("decode release: %w", err)
	}
	matcher, err := regexp.Compile(pattern)
	if err != nil {
		return "", "", "", err
	}
	for _, asset := range release.Assets {
		if matcher.MatchString(asset.Name) {
			digest := strings.TrimPrefix(strings.ToLower(asset.Digest), "sha256:")
			if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(digest) {
				return "", "", "", errors.New("the GitHub release asset does not publish a SHA-256 digest")
			}
			return asset.BrowserDownloadURL, strings.TrimPrefix(release.TagName, "v"), digest, nil
		}
	}
	return "", "", "", errors.New("the latest release does not contain the expected package")
}

func fetchExpectedChecksum(address string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	request, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("User-Agent", "ServerDeck-Agent/"+version)
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download checksum: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download checksum: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return "", err
	}
	match := regexp.MustCompile(`\b[a-f0-9]{64}\b`).FindString(strings.ToLower(string(body)))
	if match == "" {
		return "", errors.New("the checksum file did not contain a SHA-256 value")
	}
	return match, nil
}

func downloadAppArchive(address, destination string) (int64, string, error) {
	client := &http.Client{Timeout: 30 * time.Minute}
	request, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		return 0, "", err
	}
	request.Header.Set("User-Agent", "ServerDeck-Agent/"+version)
	response, err := client.Do(request)
	if err != nil {
		return 0, "", fmt.Errorf("download application: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("download application: HTTP %d", response.StatusCode)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, digest), io.LimitReader(response.Body, 2*1024*1024*1024))
	if err != nil {
		return 0, "", fmt.Errorf("save application download: %w", err)
	}
	if written == 0 {
		return 0, "", errors.New("the application download was empty")
	}
	return written, fmt.Sprintf("%x", digest.Sum(nil)), nil
}

// resolveArchiveRoot descends through a single wrapping directory (for
// archives like wordpress/ or drupal-11.x/) and then applies the catalog's
// explicit sub-path when one is defined.
func resolveArchiveRoot(staging, subPath string) (string, error) {
	root := staging
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	if len(entries) == 1 && entries[0].IsDir() {
		root = filepath.Join(root, entries[0].Name())
	}
	if subPath != "" {
		candidate := filepath.Join(root, subPath)
		if info, statErr := os.Stat(candidate); statErr == nil && info.IsDir() {
			root = candidate
		} else if info, statErr := os.Stat(filepath.Join(staging, subPath)); statErr == nil && info.IsDir() {
			root = filepath.Join(staging, subPath)
		} else {
			return "", errors.New("the downloaded archive did not contain the expected application directory")
		}
	}
	return root, nil
}

func ensurePHPExtensions(phpVersion string, extensions []string) error {
	missing := []string{}
	for _, extension := range extensions {
		packageName := "php" + phpVersion + "-" + extension
		if packageVersion(packageName) != "" {
			continue
		}
		if packageCandidate(packageName) == "" {
			return fmt.Errorf("PHP extension package %s is not available from the configured repositories", packageName)
		}
		missing = append(missing, packageName)
	}
	if len(missing) == 0 {
		return nil
	}
	arguments := append([]string{"install", "-y", "--no-install-recommends"}, missing...)
	if output, err := runLong("apt-get", append([]string{"-o", "DPkg::Lock::Timeout=30"}, arguments...)...); err != nil {
		return fmt.Errorf("install PHP extensions: %s", tail(string(output), 1200))
	}
	if err := mustRun("systemctl", "restart", "php"+phpVersion+"-fpm"); err != nil {
		return fmt.Errorf("restart PHP %s FPM: %w", phpVersion, err)
	}
	return nil
}

func removeCreatedSite(domain, webServer string) {
	configPath := filepath.Join("/etc/nginx/sites-available", domain)
	enabledPath := filepath.Join("/etc/nginx/sites-enabled", domain)
	reloadUnit := "nginx"
	if webServer == "apache" {
		configPath = filepath.Join("/etc/apache2/sites-available", domain+".conf")
		enabledPath = filepath.Join("/etc/apache2/sites-enabled", domain+".conf")
		reloadUnit = "apache2"
	}
	_ = os.Remove(enabledPath)
	_ = os.Remove(configPath)
	_ = os.Remove(filepath.Join("/var/lib/serverdeck/sites", domain+".json"))
	_ = os.RemoveAll(filepath.Join("/var/www", domain))
	_, _ = run("systemctl", "reload", reloadUnit)
}

func removeCreatedDatabase(value database) {
	if value.Engine == "PostgreSQL" {
		_, _ = run("runuser", "-u", "postgres", "--", "dropdb", "--if-exists", value.Name)
		_, _ = run("runuser", "-u", "postgres", "--", "dropuser", "--if-exists", value.Username)
	} else {
		client := "mariadb"
		if value.Engine == "MySQL" {
			client = "mysql"
		}
		cleanup := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`; DROP USER IF EXISTS '%s'@'localhost';", value.Name, value.Username)
		_, _ = run(client, "--execute", cleanup)
	}
	_ = os.Remove(filepath.Join("/var/lib/serverdeck/databases", value.Name+".json"))
}

func installApp(appID, domain string, createDB bool) (appInstallResult, error) {
	result := appInstallResult{}
	if os.Geteuid() != 0 {
		return result, errors.New("app-install must run as root")
	}
	definition, err := findAppDefinition(appID)
	if err != nil {
		return result, err
	}
	if !appDownloadVerifiable(definition) {
		return result, errors.New("this application cannot be installed because its publisher does not provide a verifiable checksum")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if len(domain) > 253 || !domainPattern.MatchString(domain) {
		return result, errors.New("invalid domain name")
	}
	if definition.database == "none" {
		createDB = false
	}

	emitProgress("preflight", "running", "Checking requirements for "+definition.name)
	webServer := detectActiveWebServer()
	if webServer == "" {
		emitProgress("preflight", "failed", "Nginx or Apache must be installed and running")
		return result, errors.New("Nginx or Apache must be installed and running")
	}
	phpVersion := newestPHPVersion()
	if phpVersion == "" {
		emitProgress("preflight", "failed", "PHP-FPM must be installed")
		return result, errors.New("PHP-FPM must be installed before installing applications")
	}
	engines := detectDatabaseEngines()
	if definition.database == "mysql" && !hasMySQLFamilyEngine(engines) {
		emitProgress("preflight", "failed", "MariaDB or MySQL must be installed")
		return result, errors.New("MariaDB or MySQL must be installed before installing " + definition.name)
	}
	if definition.database == "any" && createDB && len(engines) == 0 {
		emitProgress("preflight", "failed", "A managed database server must be installed")
		return result, errors.New("a managed database server must be installed before installing " + definition.name)
	}
	emitProgress("preflight", "completed", "Server requirements are satisfied")

	emitProgress("extensions", "running", "Preparing PHP "+phpVersion+" extensions")
	if err := ensurePHPExtensions(phpVersion, definition.extensions); err != nil {
		emitProgress("extensions", "failed", err.Error())
		return result, err
	}
	emitProgress("extensions", "completed", "PHP extensions are ready")

	downloadURL := definition.download.url
	releaseVersion := ""
	expectedChecksum := definition.download.expectedSHA256
	if definition.download.githubRepo != "" {
		emitProgress("download", "running", "Finding the latest "+definition.name+" release")
		downloadURL, releaseVersion, expectedChecksum, err = resolveGitHubDownload(definition.download.githubRepo, definition.download.assetPattern)
		if err != nil {
			emitProgress("download", "failed", err.Error())
			return result, err
		}
	}
	emitProgress("download", "running", "Downloading "+definition.name)
	staging, err := os.MkdirTemp("", "serverdeck-app-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(staging)
	archivePath := filepath.Join(staging, "application-archive")
	written, actualChecksum, err := downloadAppArchive(downloadURL, archivePath)
	if err != nil {
		emitProgress("download", "failed", err.Error())
		return result, err
	}
	if definition.download.checksumURL != "" {
		expected, checksumErr := fetchExpectedChecksum(definition.download.checksumURL)
		if checksumErr != nil {
			emitProgress("download", "failed", checksumErr.Error())
			return result, checksumErr
		}
		expectedChecksum = expected
	}
	if expectedChecksum != "" {
		if expectedChecksum != actualChecksum {
			emitProgress("download", "failed", "The downloaded file did not match the published checksum")
			return result, errors.New("the downloaded file did not match the published SHA-256 checksum")
		}
		emitProgress("download", "completed", fmt.Sprintf("Downloaded %.1f MB and verified the published checksum", float64(written)/1024/1024))
	} else {
		return result, errors.New("this application cannot be installed because its publisher does not provide a verifiable checksum")
	}

	emitProgress("site", "running", "Creating the website "+domain)
	siteValue, err := createSite(domain, "php")
	if err != nil {
		emitProgress("site", "failed", err.Error())
		return result, err
	}
	emitProgress("site", "completed", "Website created with PHP "+siteValue.PHPVersion)

	emitProgress("files", "running", "Extracting "+definition.name)
	extractionRoot := filepath.Join(staging, "extracted")
	if err := os.MkdirAll(extractionRoot, 0755); err != nil {
		removeCreatedSite(domain, webServer)
		return result, err
	}
	if err := extractAppArchive(archivePath, definition.download.format, extractionRoot); err != nil {
		emitProgress("files", "failed", err.Error())
		removeCreatedSite(domain, webServer)
		return result, err
	}
	sourceRoot, err := resolveArchiveRoot(extractionRoot, definition.archiveSubPath)
	if err != nil {
		emitProgress("files", "failed", err.Error())
		removeCreatedSite(domain, webServer)
		return result, err
	}
	_ = os.Remove(filepath.Join(siteValue.Root, "index.php"))
	_ = os.Remove(filepath.Join(siteValue.Root, "index.html"))
	if output, err := run("cp", "-a", sourceRoot+"/.", siteValue.Root+"/"); err != nil {
		emitProgress("files", "failed", tail(string(output), 800))
		removeCreatedSite(domain, webServer)
		return result, fmt.Errorf("copy application files: %s", tail(string(output), 800))
	}
	emitProgress("files", "completed", definition.name+" files are in place")

	var databaseValue *database
	if createDB {
		emitProgress("database", "running", "Creating a dedicated database")
		identifier := databaseIdentifier(definition.id, domain)
		created, dbErr := createDatabase(identifier, identifier)
		if dbErr != nil {
			emitProgress("database", "failed", dbErr.Error())
			removeCreatedSite(domain, webServer)
			return result, dbErr
		}
		databaseValue = &created
		emitProgress("database", "completed", "Database "+created.Name+" is ready")
	}

	if definition.configure != nil {
		emitProgress("configure", "running", "Writing the initial "+definition.name+" configuration")
		if err := definition.configure(siteValue.Root, domain, databaseValue); err != nil {
			emitProgress("configure", "failed", err.Error())
			if databaseValue != nil {
				removeCreatedDatabase(*databaseValue)
			}
			removeCreatedSite(domain, webServer)
			return result, err
		}
		emitProgress("configure", "completed", "Configuration written")
	}

	emitProgress("permissions", "running", "Setting file ownership for the web server")
	if output, err := run("chown", "-R", "www-data:www-data", filepath.Join("/var/www", domain)); err != nil {
		emitProgress("permissions", "failed", tail(string(output), 400))
		if databaseValue != nil {
			removeCreatedDatabase(*databaseValue)
		}
		removeCreatedSite(domain, webServer)
		return result, fmt.Errorf("set ownership: %s", tail(string(output), 400))
	}
	emitProgress("permissions", "completed", "Files are owned by www-data")

	record := installedApp{
		App:         definition.id,
		Name:        definition.name,
		Domain:      domain,
		Version:     releaseVersion,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
	}
	if databaseValue != nil {
		record.Database = databaseValue.Name
		record.DatabaseUser = databaseValue.Username
	}
	if err := os.MkdirAll("/var/lib/serverdeck/apps", 0755); err != nil {
		return result, err
	}
	encoded, _ := json.MarshalIndent(record, "", "  ")
	if err := atomicWrite(filepath.Join("/var/lib/serverdeck/apps", domain+".json"), append(encoded, '\n'), 0644); err != nil {
		return result, err
	}
	emitProgress("complete", "completed", definition.name+" is installed on "+domain)
	_ = writeAudit("app.install.completed", true, definition.id+" on "+domain)

	result = appInstallResult{
		App:      definition.id,
		Name:     definition.name,
		Domain:   domain,
		URL:      "http://" + domain + "/",
		Version:  releaseVersion,
		Database: databaseValue,
		Notes:    definition.notes,
	}
	return result, nil
}

func configureWordPress(siteRoot, domain string, db *database) error {
	if db == nil {
		return nil
	}
	keys := []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"}
	var builder strings.Builder
	builder.WriteString("<?php\n")
	fmt.Fprintf(&builder, "define( 'DB_NAME', '%s' );\n", db.Name)
	fmt.Fprintf(&builder, "define( 'DB_USER', '%s' );\n", db.Username)
	fmt.Fprintf(&builder, "define( 'DB_PASSWORD', '%s' );\n", db.Password)
	builder.WriteString("define( 'DB_HOST', 'localhost' );\n")
	builder.WriteString("define( 'DB_CHARSET', 'utf8mb4' );\n")
	builder.WriteString("define( 'DB_COLLATE', '' );\n")
	for _, key := range keys {
		salt, err := randomPassword(64)
		if err != nil {
			return err
		}
		fmt.Fprintf(&builder, "define( '%s', '%s' );\n", key, salt)
	}
	builder.WriteString("$table_prefix = 'wp_';\n")
	builder.WriteString("define( 'WP_DEBUG', false );\n")
	builder.WriteString("if ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\n")
	builder.WriteString("require_once ABSPATH . 'wp-settings.php';\n")
	return os.WriteFile(filepath.Join(siteRoot, "wp-config.php"), []byte(builder.String()), 0640)
}

func configurePHPMyAdmin(siteRoot, domain string, db *database) error {
	secret, err := randomPassword(32)
	if err != nil {
		return err
	}
	content := "<?php\ndeclare(strict_types=1);\n" +
		"$cfg['blowfish_secret'] = '" + secret + "';\n" +
		"$i = 0;\n$i++;\n" +
		"$cfg['Servers'][$i]['auth_type'] = 'cookie';\n" +
		"$cfg['Servers'][$i]['host'] = 'localhost';\n" +
		"$cfg['Servers'][$i]['compress'] = false;\n" +
		"$cfg['Servers'][$i]['AllowNoPassword'] = false;\n"
	return os.WriteFile(filepath.Join(siteRoot, "config.inc.php"), []byte(content), 0640)
}

func configureOpenCart(siteRoot, domain string, db *database) error {
	for _, path := range []string{filepath.Join(siteRoot, "config.php"), filepath.Join(siteRoot, "admin", "config.php")} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(""), 0660); err != nil {
			return err
		}
	}
	return nil
}

func configureDolibarr(siteRoot, domain string, db *database) error {
	documents := filepath.Join("/var/www", domain, "documents")
	if err := os.MkdirAll(documents, 0750); err != nil {
		return err
	}
	confDir := filepath.Join(siteRoot, "conf")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(confDir, "conf.php"), []byte(""), 0660)
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
		loadState, subState, activeEnter, pid, memory := getServiceSystemdProperties(name)
		active := strings.TrimSpace(systemctl("is-active", name+".service")) == "active"
		if name == "ufw" {
			active = firewallIsActive()
		}
		var s service
		s.Name = name
		s.Installed = strings.TrimSpace(loadState) == "loaded"
		s.Active = active
		s.Description = managedServices[name]
		if active {
			s.SubState = subState
			s.PID = pid
			s.Memory = memory
			s.Uptime = activeEnter
		}
		services = append(services, s)
	}
	phpUnits, _ := runOutputWithTimeout(defaultTimeout, "systemctl", "list-unit-files", "php*-fpm.service", "--no-legend", "--no-pager")
	for _, line := range strings.Split(string(phpUnits), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".service")
		_, subState, activeEnter, pid, memory := getServiceSystemdProperties(name)
		active := strings.TrimSpace(systemctl("is-active", fields[0])) == "active"
		var s service
		s.Name = name
		s.Installed = true
		s.Active = active
		s.Description = "PHP application runtime"
		if active {
			s.SubState = subState
			s.PID = pid
			s.Memory = memory
			s.Uptime = activeEnter
		}
		services = append(services, s)
	}
	sites, _ := listSites()
	for _, site := range sites {
		if site.Service == "" {
			continue
		}
		_, subState, activeEnter, pid, memory := getServiceSystemdProperties(site.Service)
		active := strings.TrimSpace(systemctl("is-active", site.Service+".service")) == "active"
		var s service
		s.Name = site.Service
		s.Installed = true
		s.Active = active
		s.Description = "Node.js project for " + site.Domain
		if active {
			s.SubState = subState
			s.PID = pid
			s.Memory = memory
			s.Uptime = activeEnter
		}
		services = append(services, s)
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	return services, nil
}

func getServiceSystemdProperties(name string) (loadState, subState, activeEnter string, pid int, memory int64) {
	output := systemctl("show", name+".service", "--property=LoadState,SubState,ActiveEnterTimestamp,MainPID,MemoryCurrent")
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "LoadState":
			loadState = val
		case "SubState":
			subState = val
		case "ActiveEnterTimestamp":
			if val != "[not set]" && val != "" {
				activeEnter = val
			}
		case "MainPID":
			if p, err := strconv.Atoi(val); err == nil {
				pid = p
			}
		case "MemoryCurrent":
			if val != "[not set]" && val != "" {
				if m, err := strconv.ParseInt(val, 10, 64); err == nil {
					memory = m
				}
			}
		}
	}
	return
}

func systemctl(arguments ...string) string {
	output, _ := runOutputWithTimeout(defaultTimeout, "systemctl", arguments...)
	return string(output)
}

var allowedConfigs = map[string]string{
	"nginx":    "/etc/nginx/nginx.conf",
	"apache":   "/etc/apache2/apache2.conf",
	"redis":    "/etc/redis/redis.conf",
	"fail2ban": "/etc/fail2ban/jail.conf",
}

func getSoftwareConfigPath(id string) (string, error) {
	if strings.HasPrefix(id, "site-") {
		domain := strings.TrimPrefix(id, "site-")
		metadataPath := filepath.Join("/var/lib/serverdeck/sites", domain+".json")
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			return "", fmt.Errorf("site not found: %w", err)
		}
		var value site
		if err := json.Unmarshal(data, &value); err != nil {
			return "", fmt.Errorf("read site metadata: %w", err)
		}
		path := filepath.Join("/etc/nginx/sites-available", domain)
		if value.WebServer == "apache" {
			path = filepath.Join("/etc/apache2/sites-available", domain+".conf")
		}
		return path, nil
	}
	if path, ok := allowedConfigs[id]; ok {
		return path, nil
	}
	if id == "mysql" || id == "mariadb" {
		for _, path := range []string{
			"/etc/mysql/mariadb.conf.d/50-server.cnf",
			"/etc/mysql/mysql.conf.d/mysqld.cnf",
			"/etc/mysql/my.cnf",
		} {
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}
		return "", errors.New("database configuration file not found")
	}
	if id == "postgresql" {
		matches, _ := filepath.Glob("/etc/postgresql/*/main/postgresql.conf")
		if len(matches) > 0 {
			return matches[0], nil
		}
		return "", errors.New("postgresql configuration file not found")
	}
	if strings.HasPrefix(id, "php") {
		ver := strings.TrimPrefix(id, "php")
		if len(ver) > 1 && !strings.Contains(ver, ".") {
			ver = string(ver[0]) + "." + ver[1:]
		}
		path := fmt.Sprintf("/etc/php/%s/fpm/php.ini", ver)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
		return "", fmt.Errorf("php configuration not found for version %s", ver)
	}
	return "", fmt.Errorf("unsupported configuration identifier: %s", id)
}

func readSoftwareConfig(id string) (string, error) {
	path, err := getSoftwareConfigPath(id)
	if err != nil {
		return "", err
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func writeSoftwareConfig(id, encodedContent string) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("software-config-write must run as root")
	}
	path, err := getSoftwareConfigPath(id)
	if err != nil {
		return "", err
	}
	content, err := base64.RawURLEncoding.DecodeString(encodedContent)
	if err != nil {
		content, err = base64.StdEncoding.DecodeString(encodedContent)
		if err != nil {
			return "", errors.New("invalid encoded content")
		}
	}

	backupPath := path + ".bak"
	if originalBytes, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(backupPath, originalBytes, 0644)
	}

	if err := atomicWrite(path, content, 0644); err != nil {
		return "", err
	}

	var testCmd *exec.Cmd
	if id == "nginx" {
		testCmd2, cancelTestcmd := commandContext(defaultTimeout, "nginx", "-t")
		testCmd = testCmd2
		defer cancelTestcmd()
	} else if id == "apache" {
		testCmd2, cancelTestcmd2 := commandContext(defaultTimeout, "apache2ctl", "configtest")
		testCmd = testCmd2
		defer cancelTestcmd2()
	}

	if testCmd != nil {
		if output, err := testCmd.CombinedOutput(); err != nil {
			if backupBytes, backupErr := os.ReadFile(backupPath); backupErr == nil {
				_ = os.WriteFile(path, backupBytes, 0644)
			}
			outStr := string(output)
			if len(outStr) > 800 {
				outStr = outStr[len(outStr)-800:]
			}
			return "", fmt.Errorf("configuration validation failed: %s", outStr)
		}
	}

	var serviceName string
	switch {
	case id == "nginx":
		serviceName = "nginx"
	case id == "apache":
		serviceName = "apache2"
	case id == "mysql" || id == "mariadb":
		if packageVersion("mariadb-server") != "" {
			serviceName = "mariadb"
		} else {
			serviceName = "mysql"
		}
	case id == "postgresql":
		serviceName = "postgresql"
	case id == "redis":
		serviceName = "redis-server"
	case id == "fail2ban":
		serviceName = "fail2ban"
	case strings.HasPrefix(id, "php"):
		ver := strings.TrimPrefix(id, "php")
		if len(ver) > 1 && !strings.Contains(ver, ".") {
			ver = string(ver[0]) + "." + ver[1:]
		}
		serviceName = "php" + ver + "-fpm"
	}

	if serviceName != "" {
		_, _ = run("systemctl", "restart", serviceName)
	}

	_ = writeAudit("software.config_updated", true, path)
	return string(content), nil
}

func deleteSite(domain string, deleteRoot bool) error {
	if os.Geteuid() != 0 {
		return errors.New("site-delete must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	metadataPath := filepath.Join("/var/lib/serverdeck/sites", domain+".json")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("site not found: %w", err)
	}
	var value site
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("read site metadata: %w", err)
	}

	configPath := filepath.Join("/etc/nginx/sites-available", domain)
	enabledPath := filepath.Join("/etc/nginx/sites-enabled", domain)
	if value.WebServer == "apache" {
		configPath = filepath.Join("/etc/apache2/sites-available", domain+".conf")
		enabledPath = filepath.Join("/etc/apache2/sites-enabled", domain+".conf")
	}

	_ = os.Remove(enabledPath)
	_ = os.Remove(configPath)
	_ = os.Remove(metadataPath)
	// Drop any staging record so a deleted staging site cannot linger in the
	// staging list pointing at a site that no longer exists.
	removeStagingRecord(domain)

	if deleteRoot {
		parent := filepath.Dir(value.Root)
		if strings.HasPrefix(parent, "/var/www/") && parent != "/var/www/" && parent != "/var/www" {
			_ = os.RemoveAll(parent)
		}
		_ = os.RemoveAll(filepath.Join(managedTrashRoot, domain))
	}

	serviceName := "nginx"
	if value.WebServer == "apache" {
		serviceName = "apache2"
	}
	_, _ = run("systemctl", "reload", serviceName)

	_ = writeAudit("site.deleted", true, domain)
	return nil
}

func updateSite(domain, newRoot, phpVersion string) error {
	if os.Geteuid() != 0 {
		return errors.New("site-update must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	newRoot = strings.TrimSpace(newRoot)

	metadataPath := filepath.Join("/var/lib/serverdeck/sites", domain+".json")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("site not found: %w", err)
	}
	var value site
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("read site metadata: %w", err)
	}

	configPath := filepath.Join("/etc/nginx/sites-available", domain)
	if value.WebServer == "apache" {
		configPath = filepath.Join("/etc/apache2/sites-available", domain+".conf")
	}

	configBytes, err := os.ReadFile(configPath)
	if err == nil {
		configContent := string(configBytes)
		configContent = strings.ReplaceAll(configContent, value.Root, newRoot)

		if phpVersion != "" && value.PHPVersion != phpVersion {
			oldSocket := fmt.Sprintf("php%s-fpm.sock", value.PHPVersion)
			newSocket := fmt.Sprintf("php%s-fpm.sock", phpVersion)
			configContent = strings.ReplaceAll(configContent, oldSocket, newSocket)
		}

		if err := atomicWrite(configPath, []byte(configContent), 0644); err != nil {
			return err
		}

		var testCmd *exec.Cmd
		if value.WebServer == "nginx" {
			testCmd2, cancelTestcmd3 := commandContext(defaultTimeout, "nginx", "-t")
			testCmd = testCmd2
			defer cancelTestcmd3()
		} else {
			testCmd2, cancelTestcmd4 := commandContext(defaultTimeout, "apache2ctl", "configtest")
			testCmd = testCmd2
			defer cancelTestcmd4()
		}
		if output, err := testCmd.CombinedOutput(); err != nil {
			_ = atomicWrite(configPath, configBytes, 0644)
			return fmt.Errorf("configuration validation failed: %s", tail(string(output), 800))
		}
	}

	if err := os.MkdirAll(newRoot, 0755); err != nil {
		return fmt.Errorf("create new document root: %w", err)
	}

	value.Root = newRoot
	if phpVersion != "" {
		value.PHPVersion = phpVersion
	}

	metadata, _ := json.MarshalIndent(value, "", "  ")
	if err := atomicWrite(metadataPath, append(metadata, '\n'), 0644); err != nil {
		return err
	}

	serviceName := "nginx"
	if value.WebServer == "apache" {
		serviceName = "apache2"
	}
	_, _ = run("systemctl", "reload", serviceName)

	_ = writeAudit("site.updated", true, domain)
	return nil
}

func deleteDatabase(name string) error {
	if os.Geteuid() != 0 {
		return errors.New("database-delete must run as root")
	}
	name = strings.ToLower(strings.TrimSpace(name))

	metadataPath := filepath.Join("/var/lib/serverdeck/databases", name+".json")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return fmt.Errorf("database not found: %w", err)
	}
	var value database
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("read database metadata: %w", err)
	}

	if value.Engine == "PostgreSQL" {
		_, _ = run("runuser", "-u", "postgres", "--", "dropdb", "--if-exists", name)
		_, _ = run("runuser", "-u", "postgres", "--", "dropuser", "--if-exists", value.Username)
	} else {
		databaseClient := "mariadb"
		if packageVersion("mysql-server") != "" && packageVersion("mariadb-server") == "" {
			databaseClient = "mysql"
		}
		sql := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`; DROP USER IF EXISTS '%s'@'localhost';", name, value.Username)
		_, _ = run(databaseClient, "--execute", sql)
	}

	_ = os.Remove(metadataPath)
	_ = writeAudit("database.deleted", true, name)
	return nil
}

func createMailDomain(domain string) error {
	if os.Geteuid() != 0 {
		return errors.New("mail-domain-create must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !domainPattern.MatchString(domain) {
		return errors.New("invalid mail domain")
	}

	vhostsPath := "/etc/postfix/vhosts"
	existing, err := os.ReadFile(vhostsPath)
	if err != nil {
		existing = []byte("")
	}
	lines := strings.Split(string(existing), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) > 0 && strings.ToLower(parts[0]) == domain {
			return errors.New("mail domain already exists")
		}
	}

	newContent := string(existing)
	if len(newContent) > 0 && !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	newContent += domain + " OK\n"
	if err := atomicWrite(vhostsPath, []byte(newContent), 0600); err != nil {
		return err
	}

	_, _ = run("postmap", vhostsPath)
	_, _ = run("systemctl", "reload", "postfix")

	_ = writeAudit("mail.domain.created", true, domain)
	return nil
}

func deleteMailDomain(domain string) error {
	if os.Geteuid() != 0 {
		return errors.New("mail-domain-delete must run as root")
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	vhostsPath := "/etc/postfix/vhosts"
	existing, err := os.ReadFile(vhostsPath)
	if err == nil {
		lines := strings.Split(string(existing), "\n")
		var newLines []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			parts := strings.Fields(trimmed)
			if len(parts) > 0 && strings.ToLower(parts[0]) == domain {
				continue
			}
			newLines = append(newLines, line)
		}
		_ = atomicWrite(vhostsPath, []byte(strings.Join(newLines, "\n")+"\n"), 0600)
		_, _ = run("postmap", vhostsPath)
	}

	vmapsPath := "/etc/postfix/vmaps"
	if vmapsBytes, err := os.ReadFile(vmapsPath); err == nil {
		lines := strings.Split(string(vmapsBytes), "\n")
		var newLines []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			parts := strings.Fields(trimmed)
			if len(parts) > 0 {
				email := strings.ToLower(parts[0])
				idx := strings.Index(email, "@")
				if idx > 0 && email[idx+1:] == domain {
					continue
				}
			}
			newLines = append(newLines, line)
		}
		_ = atomicWrite(vmapsPath, []byte(strings.Join(newLines, "\n")+"\n"), 0600)
		_, _ = run("postmap", vmapsPath)
	}

	dovecotUsersPath := "/etc/dovecot/users"
	if usersBytes, err := os.ReadFile(dovecotUsersPath); err == nil {
		lines := strings.Split(string(usersBytes), "\n")
		var newLines []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			parts := strings.Split(trimmed, ":")
			if len(parts) > 0 {
				email := strings.ToLower(parts[0])
				idx := strings.Index(email, "@")
				if idx > 0 && email[idx+1:] == domain {
					continue
				}
			}
			newLines = append(newLines, line)
		}
		_ = atomicWrite(dovecotUsersPath, []byte(strings.Join(newLines, "\n")+"\n"), 0600)
	}

	_ = os.RemoveAll(filepath.Join("/etc/opendkim/keys", domain))

	_, _ = run("systemctl", "reload", "postfix")
	_, _ = run("systemctl", "reload", "dovecot")

	_ = writeAudit("mail.domain.deleted", true, domain)
	return nil
}

func createMailAccount(email, password string) error {
	if os.Geteuid() != 0 {
		return errors.New("mail-account-create must run as root")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	idx := strings.Index(email, "@")
	if idx <= 0 || idx >= len(email)-1 {
		return errors.New("invalid email address format")
	}
	domain := email[idx+1:]

	vhostsPath := "/etc/postfix/vhosts"
	existingVhosts, err := os.ReadFile(vhostsPath)
	if err != nil {
		return errors.New("mail domain does not exist")
	}
	domainExists := false
	for _, line := range strings.Split(string(existingVhosts), "\n") {
		parts := strings.Fields(line)
		if len(parts) > 0 && strings.ToLower(parts[0]) == domain {
			domainExists = true
			break
		}
	}
	if !domainExists {
		return errors.New("mail domain must be created in virtual domains first")
	}

	vmapsPath := "/etc/postfix/vmaps"
	existingVmaps, err := os.ReadFile(vmapsPath)
	if err == nil {
		for _, line := range strings.Split(string(existingVmaps), "\n") {
			parts := strings.Fields(line)
			if len(parts) > 0 && strings.ToLower(parts[0]) == email {
				return errors.New("mailbox account already exists")
			}
		}
	}

	// -stdin keeps the password out of the process list.
	output, err := runWithStdin(defaultTimeout, password+"\n", "openssl", "passwd", "-6", "-stdin")
	if err != nil {
		return fmt.Errorf("generate secure password hash: %s", tail(string(output), 500))
	}
	passHash := strings.TrimSpace(string(output))

	newVmaps := string(existingVmaps)
	if len(newVmaps) > 0 && !strings.HasSuffix(newVmaps, "\n") {
		newVmaps += "\n"
	}
	newVmaps += fmt.Sprintf("%s %s/%s/\n", email, domain, email[:idx])
	if err := atomicWrite(vmapsPath, []byte(newVmaps), 0600); err != nil {
		return err
	}

	dovecotUsersPath := "/etc/dovecot/users"
	existingUsers, err := os.ReadFile(dovecotUsersPath)
	if err != nil {
		existingUsers = []byte("")
	}
	newUsers := string(existingUsers)
	if len(newUsers) > 0 && !strings.HasSuffix(newUsers, "\n") {
		newUsers += "\n"
	}
	newUsers += fmt.Sprintf("%s:%s:5000:5000::/var/mail/vhosts/%s/%s\n", email, passHash, domain, email[:idx])
	if err := atomicWrite(dovecotUsersPath, []byte(newUsers), 0600); err != nil {
		return err
	}

	_, _ = run("postmap", vmapsPath)
	_, _ = run("systemctl", "reload", "postfix")
	_, _ = run("systemctl", "reload", "dovecot")

	_ = writeAudit("mail.account.created", true, email)
	return nil
}

func deleteMailAccount(email string) error {
	if os.Geteuid() != 0 {
		return errors.New("mail-account-delete must run as root")
	}
	email = strings.ToLower(strings.TrimSpace(email))

	vmapsPath := "/etc/postfix/vmaps"
	if vmapsBytes, err := os.ReadFile(vmapsPath); err == nil {
		lines := strings.Split(string(vmapsBytes), "\n")
		var newLines []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			parts := strings.Fields(trimmed)
			if len(parts) > 0 && strings.ToLower(parts[0]) == email {
				continue
			}
			newLines = append(newLines, line)
		}
		_ = atomicWrite(vmapsPath, []byte(strings.Join(newLines, "\n")+"\n"), 0600)
		_, _ = run("postmap", vmapsPath)
	}

	dovecotUsersPath := "/etc/dovecot/users"
	if usersBytes, err := os.ReadFile(dovecotUsersPath); err == nil {
		lines := strings.Split(string(usersBytes), "\n")
		var newLines []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			parts := strings.Split(trimmed, ":")
			if len(parts) > 0 && strings.ToLower(parts[0]) == email {
				continue
			}
			newLines = append(newLines, line)
		}
		_ = atomicWrite(dovecotUsersPath, []byte(strings.Join(newLines, "\n")+"\n"), 0600)
	}

	_, _ = run("systemctl", "reload", "postfix")
	_, _ = run("systemctl", "reload", "dovecot")

	_ = writeAudit("mail.account.deleted", true, email)
	return nil
}

func createMailAlias(source, destination string) error {
	if os.Geteuid() != 0 {
		return errors.New("mail-alias-create must run as root")
	}
	source = strings.ToLower(strings.TrimSpace(source))
	destination = strings.TrimSpace(destination)

	var domain string
	if strings.HasPrefix(source, "@") {
		domain = source[1:]
	} else {
		idx := strings.Index(source, "@")
		if idx <= 0 || idx >= len(source)-1 {
			return errors.New("invalid source address format")
		}
		domain = source[idx+1:]
	}

	vhostsPath := "/etc/postfix/vhosts"
	existingVhosts, err := os.ReadFile(vhostsPath)
	if err != nil {
		return errors.New("mail domain does not exist")
	}
	domainExists := false
	for _, line := range strings.Split(string(existingVhosts), "\n") {
		parts := strings.Fields(line)
		if len(parts) > 0 && strings.ToLower(parts[0]) == domain {
			domainExists = true
			break
		}
	}
	if !domainExists {
		return errors.New("mail domain must be created in virtual domains first")
	}

	virtualPath := "/etc/postfix/virtual"
	existingVirtual, err := os.ReadFile(virtualPath)
	if err == nil {
		for _, line := range strings.Split(string(existingVirtual), "\n") {
			parts := strings.Fields(line)
			if len(parts) > 0 && strings.ToLower(parts[0]) == source {
				return errors.New("forwarding mapping already exists for this address")
			}
		}
	}

	newContent := string(existingVirtual)
	if len(newContent) > 0 && !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	newContent += fmt.Sprintf("%s %s\n", source, destination)
	if err := atomicWrite(virtualPath, []byte(newContent), 0600); err != nil {
		return err
	}

	_, _ = run("postmap", virtualPath)
	_, _ = run("systemctl", "reload", "postfix")

	_ = writeAudit("mail.alias.created", true, source+" -> "+destination)
	return nil
}

func deleteMailAlias(source string) error {
	if os.Geteuid() != 0 {
		return errors.New("mail-alias-delete must run as root")
	}
	source = strings.ToLower(strings.TrimSpace(source))

	virtualPath := "/etc/postfix/virtual"
	if virtualBytes, err := os.ReadFile(virtualPath); err == nil {
		lines := strings.Split(string(virtualBytes), "\n")
		var newLines []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			parts := strings.Fields(trimmed)
			if len(parts) > 0 && strings.ToLower(parts[0]) == source {
				continue
			}
			newLines = append(newLines, line)
		}
		_ = atomicWrite(virtualPath, []byte(strings.Join(newLines, "\n")+"\n"), 0600)
		_, _ = run("postmap", virtualPath)
	}

	_, _ = run("systemctl", "reload", "postfix")
	_ = writeAudit("mail.alias.deleted", true, source)
	return nil
}

// siteDatabase resolves which database belongs to a site.
//
// The association has lived in two places for historical reasons: apps ServerDeck
// installed record it in their app file, while a site created on its own had
// nowhere to record one at all. The site record is now the primary home, with the
// app record as a fallback so existing installs keep working.
//
// Getting this wrong is not cosmetic. Backups ask this question to decide whether
// to include a database, so a site whose database cannot be resolved is backed up
// as files only — which cannot restore it.
func siteDatabase(domain string) (name string, user string, found bool) {
	domain = normaliseHost(domain)

	if value, err := readSiteMetadata(domain); err == nil && value.Database != "" {
		return value.Database, value.DatabaseUser, true
	}
	// Any installed app, not only WordPress: Drupal, Joomla and the rest all
	// have databases, and gating on WordPress silently dropped them.
	if app, err := readInstalledApp(domain); err == nil && app.Database != "" {
		return app.Database, app.DatabaseUser, true
	}
	return "", "", false
}

// writeSiteMetadata persists a site record.
func writeSiteMetadata(value site) error {
	// The password is deliberately dropped: it is shown once at creation and
	// then lives only in the application's own configuration file.
	stored := value
	stored.DatabasePassword = ""
	encoded, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join("/var/lib/serverdeck/sites", normaliseHost(value.Domain)+".json"),
		append(encoded, '\n'), 0644)
}
