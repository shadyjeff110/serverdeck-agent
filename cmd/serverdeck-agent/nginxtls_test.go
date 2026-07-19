package main

import (
	"strings"
	"testing"
)

const certPath = "/etc/letsencrypt/live/example.com"

// The plain vhost shape this agent generates for a subdomain.
const subdomainVhost = `server {
    listen 80;
    listen [::]:80;
    server_name blog.example.com;
    root /var/www/blog.example.com/public;
    index index.html;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;
    }
}
`

// An apex site, which also carries a canonical redirect block ahead of the
// serving block.
const apexVhost = `server {
    listen 80;
    listen [::]:80;
    server_name www.example.com;
    return 301 $scheme://example.com$request_uri;
}

server {
    listen 80;
    listen [::]:80;
    server_name example.com;
    root /var/www/example.com/public;
    index index.html;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }
}
`

func TestTLSListenersLandOnTheServingBlock(t *testing.T) {
	updated, err := nginxTLSConfig(apexVhost, "example.com", certPath, canonicalNonWWW)
	if err != nil {
		t.Fatal(err)
	}

	blocks := splitServerBlocks(updated)
	for _, block := range blocks {
		hasRoot := strings.Contains(block, "root ")
		hasTLS := strings.Contains(block, "listen 443 ssl")
		if hasTLS && !hasRoot {
			t.Error("TLS listeners were added to a redirect block instead of the serving block")
		}
		if hasRoot && !hasTLS {
			t.Error("the serving block did not get TLS listeners")
		}
	}
}

func TestServingBlockStopsAnsweringOnPlainHTTP(t *testing.T) {
	updated, err := nginxTLSConfig(subdomainVhost, "blog.example.com", certPath, canonicalNonWWW)
	if err != nil {
		t.Fatal(err)
	}
	for _, block := range splitServerBlocks(updated) {
		if strings.Contains(block, "root ") && listen80.MatchString(block) {
			t.Error("the serving block still listens on port 80; HTTP would bypass TLS")
		}
	}
}

func TestHTTPIsRedirectedToHTTPS(t *testing.T) {
	updated, err := nginxTLSConfig(subdomainVhost, "blog.example.com", certPath, canonicalNonWWW)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(updated, "return 301 https://blog.example.com$request_uri;") {
		t.Errorf("no HTTP to HTTPS redirect was added:\n%s", updated)
	}
	if !strings.Contains(updated, "listen 80;") {
		t.Error("nothing listens on port 80, so HTTP visitors would get a connection error")
	}
}

// www and http must both land on the canonical HTTPS URL in one hop, not by
// chaining a plain-HTTP redirect into an HTTPS one.
func TestCanonicalAndTLSRedirectInOneHop(t *testing.T) {
	updated, err := nginxTLSConfig(apexVhost, "example.com", certPath, canonicalNonWWW)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(updated, "return 301 https://example.com$request_uri;") {
		t.Errorf("expected a single-hop redirect to the canonical HTTPS host:\n%s", updated)
	}
	if strings.Contains(updated, "return 301 $scheme://") {
		t.Error("the old scheme-relative redirect survived; www over HTTP would take two hops")
	}
	// The redirect block must cover both names so www is not left unserved.
	if !strings.Contains(updated, "server_name example.com www.example.com;") {
		t.Errorf("the redirect block does not cover both names:\n%s", updated)
	}
}

func TestReissuingIsIdempotent(t *testing.T) {
	once, err := nginxTLSConfig(subdomainVhost, "blog.example.com", certPath, canonicalNonWWW)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := nginxTLSConfig(once, "blog.example.com", certPath, canonicalNonWWW)
	if err != nil {
		t.Fatal(err)
	}
	if once != twice {
		t.Error("re-running the rewrite changed the configuration again")
	}
}

// A location block's closing brace must not be mistaken for the end of the
// server block.
func TestNestedBlocksDoNotTerminateEarly(t *testing.T) {
	blocks := splitServerBlocks(subdomainVhost)
	if len(blocks) != 1 {
		t.Fatalf("expected one server block, got %d", len(blocks))
	}
	if !strings.Contains(blocks[0], "fastcgi_pass") {
		t.Error("the block was cut short at a nested location brace")
	}
}

func TestApexVhostSplitsIntoTwoBlocks(t *testing.T) {
	if blocks := splitServerBlocks(apexVhost); len(blocks) != 2 {
		t.Fatalf("expected two server blocks, got %d", len(blocks))
	}
}

// A proxied site has no root directive; the rewrite must still find a serving
// block rather than giving up or picking a redirect block.
func TestProxiedSiteWithoutRoot(t *testing.T) {
	proxied := `server {
    listen 80;
    listen [::]:80;
    server_name app.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
    }
}
`
	updated, err := nginxTLSConfig(proxied, "app.example.com", certPath, canonicalNonWWW)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(updated, "listen 443 ssl") {
		t.Error("a proxied site did not get TLS listeners")
	}
	if !strings.Contains(updated, "proxy_pass") {
		t.Error("the proxy configuration was lost")
	}
}

func TestMalformedConfigIsRejected(t *testing.T) {
	if _, err := nginxTLSConfig("server {\n    listen 80;\n", "example.com", certPath, canonicalNonWWW); err == nil {
		t.Error("an unterminated server block should be refused, not rewritten")
	}
}
