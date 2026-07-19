package main

import "strings"

// Deciding when a site should also answer on a `www.` name.
//
// The convention every hosting panel follows is narrow: a registrable domain
// (example.com) also answers on www.example.com, because visitors type both. A
// subdomain does not — nobody visits www.blog.example.com, and no registrar or
// panel creates that record.
//
// Adding it anyway is not merely untidy. Certificate issuance asks the CA to
// validate every name on the vhost, so a www alias on a subdomain guarantees a
// failed validation before the fallback succeeds, and Let's Encrypt caps failed
// validations at five per hostname per hour. The wasted attempts come out of a
// budget the user may need.
//
// Telling the two apart means knowing where the registrable part starts, which
// is not "count the dots": example.co.uk is registrable while blog.example.com
// is not, and both have two dots. The authoritative answer is the Public Suffix
// List, which is far too large to embed in an agent meant to stay small, so the
// common multi-label suffixes are listed below. A suffix that is missing causes
// a site to lose a www alias it could have had — a cosmetic miss — rather than
// producing a name that cannot be validated.

// multiLabelPublicSuffixes are registries that allocate names one level down,
// so example.co.uk is registrable and co.uk itself is not.
var multiLabelPublicSuffixes = map[string]bool{
	// United Kingdom
	"co.uk": true, "org.uk": true, "me.uk": true, "ltd.uk": true, "plc.uk": true,
	"net.uk": true, "sch.uk": true, "ac.uk": true, "gov.uk": true, "nhs.uk": true,
	// Australia and New Zealand
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"id.au": true, "asn.au": true,
	"co.nz": true, "net.nz": true, "org.nz": true, "govt.nz": true, "ac.nz": true,
	// Africa
	"co.za": true, "org.za": true, "net.za": true, "gov.za": true, "ac.za": true,
	"com.ng": true, "co.ke": true, "com.gh": true, "com.eg": true,
	// South and East Asia
	"co.in": true, "net.in": true, "org.in": true, "firm.in": true, "gen.in": true,
	"ind.in": true, "ac.in": true, "edu.in": true, "gov.in": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true, "go.jp": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"com.sg": true, "com.my": true, "com.hk": true, "com.tw": true, "com.ph": true,
	"com.vn": true, "com.pk": true, "com.bd": true, "com.np": true, "com.lk": true,
	"co.kr": true, "co.th": true, "in.th": true, "co.id": true,
	// Europe, Middle East
	"com.tr": true, "com.pl": true, "com.ua": true, "com.ru": true, "com.es": true,
	"co.il": true, "com.sa": true, "com.ae": true, "com.qa": true, "com.kw": true,
	"com.gr": true, "com.pt": true, "com.cy": true, "co.at": true,
	// Americas
	"com.br": true, "net.br": true, "org.br": true, "com.mx": true, "com.ar": true,
	"com.co": true, "com.pe": true, "com.ec": true, "com.uy": true, "com.ve": true,
	"com.bo": true, "com.py": true, "com.do": true, "com.gt": true, "com.sv": true,
	"com.hn": true, "com.ni": true, "com.pa": true, "co.cr": true, "com.cu": true,
}

// normaliseHost lowercases, trims, and drops the root label's trailing dot, so
// every comparison and every rendered name agrees on one spelling.
func normaliseHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// isRegistrableDomain reports whether a host is the domain itself rather than a
// name below it. example.com and example.co.uk are; blog.example.com is not.
func isRegistrableDomain(host string) bool {
	host = normaliseHost(host)
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	if len(labels) == 2 {
		// example.com — registrable unless the whole thing is itself a suffix,
		// which would mean there is no name to register.
		return !multiLabelPublicSuffixes[host]
	}
	if len(labels) == 3 {
		return multiLabelPublicSuffixes[strings.Join(labels[1:], ".")]
	}
	return false
}

// wwwAliasFor returns the www name a vhost should also answer on, and whether
// there is one at all.
func wwwAliasFor(host string) (string, bool) {
	host = normaliseHost(host)
	// A site already published as www.example.com must not become
	// www.www.example.com. Its bare form is a separate site the user can create.
	if strings.HasPrefix(host, "www.") {
		return "", false
	}
	if !isRegistrableDomain(host) {
		return "", false
	}
	return "www." + host, true
}

// serverNames lists every name a vhost should answer on, in the order they
// belong in the configuration.
func serverNames(host string) []string {
	names := []string{normaliseHost(host)}
	if alias, ok := wwwAliasFor(host); ok {
		names = append(names, alias)
	}
	return names
}

// Canonical host selection.
//
// Serving the same content on both example.com and www.example.com without
// choosing between them is duplicate content: search engines index two URLs for
// every page and split the ranking signals, and sessions set on one host are not
// visible on the other. The fix is to pick one and redirect the other with a
// 301.
//
// Neither direction is objectively correct — www has a DNS argument at the apex,
// non-www is shorter and the more common modern default — so non-www is the
// default here and the choice is per-site. What matters is that a site commits
// to one, and that switching an established site is a deliberate act, because
// reversing a canonical host costs search ranking while engines re-learn it.
type canonicalHost string

const (
	canonicalNonWWW canonicalHost = "non-www"
	canonicalWWW    canonicalHost = "www"
	// canonicalNone serves both names without redirecting, which is what sites
	// created before this existed already do.
	canonicalNone canonicalHost = "none"
)

func parseCanonicalHost(value string) canonicalHost {
	switch canonicalHost(strings.ToLower(strings.TrimSpace(value))) {
	case canonicalWWW:
		return canonicalWWW
	case canonicalNone:
		return canonicalNone
	default:
		return canonicalNonWWW
	}
}

// canonicalRedirect returns the host to redirect away from and the host to send
// visitors to, or false when no redirect applies.
//
// Only a domain with a www alias can have one: a subdomain has a single name and
// nothing to redirect.
func canonicalRedirect(host string, preference canonicalHost) (from, to string, ok bool) {
	alias, hasAlias := wwwAliasFor(host)
	if !hasAlias || preference == canonicalNone {
		return "", "", false
	}
	bare := normaliseHost(host)
	if preference == canonicalWWW {
		return bare, alias, true
	}
	return alias, bare, true
}

// Response headers added to every new site.
//
// Chosen because they are safe on an arbitrary site: each one closes a specific
// hole without assuming anything about the content. Deliberately absent is
// Strict-Transport-Security, which is not safe to apply automatically — browsers
// cache it for its full duration, so a site whose certificate later lapses
// becomes unreachable rather than merely insecure, and there is no way to undo
// it from the server. That belongs behind a deliberate per-site opt-in.
//
// Content-Security-Policy is absent for the same reason in reverse: any useful
// value depends entirely on what the site loads, and a generic one would break
// most sites on the first page view.
const nginxSecurityHeaders = `    # Set by ServerDeck. Safe defaults; see the docs before adding HSTS or CSP.
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
`

// Ubuntu releases past their support window.
//
// Kept as a list of what is finished rather than a list of what works. The
// inverse — naming the releases that are supported — silently blocks every
// release published after the code was written, which is how a server running a
// newer Ubuntu than the author had was told its packages were unavailable.
//
// An unknown codename is treated as supported. The cost of being wrong that way
// is an enable that fails and rolls back, with the repository's own error shown.
// The cost of being wrong the other way is a capability quietly withheld with a
// misleading explanation.
var endOfLifeUbuntuReleases = map[string]bool{
	"warty": true, "hoary": true, "breezy": true, "dapper": true, "edgy": true,
	"feisty": true, "gutsy": true, "hardy": true, "intrepid": true, "jaunty": true,
	"karmic": true, "lucid": true, "maverick": true, "natty": true, "oneiric": true,
	"precise": true, "quantal": true, "raring": true, "saucy": true, "trusty": true,
	"utopic": true, "vivid": true, "wily": true, "xenial": true, "yakkety": true,
	"zesty": true, "artful": true, "bionic": true, "cosmic": true, "disco": true,
	"eoan": true, "focal": true, "groovy": true, "hirsute": true, "impish": true,
	"kinetic": true, "lunar": true, "mantic": true,
}

func isEndOfLifeUbuntu(codename string) bool {
	return endOfLifeUbuntuReleases[strings.ToLower(strings.TrimSpace(codename))]
}
