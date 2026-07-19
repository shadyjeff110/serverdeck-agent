package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Turning a plain-HTTP nginx vhost into an HTTPS one.
//
// certbot is invoked with `certonly` for nginx, which obtains the certificate
// but never edits the configuration. Everything below is what `--nginx` would
// otherwise have done, done explicitly so the result is predictable and can be
// tested without a live certificate authority.
//
// Two things were missing before. The TLS listeners were inserted into the first
// `server {` in the file, which stopped being the serving block once a canonical
// redirect block was added ahead of it. And nothing ever redirected HTTP to
// HTTPS, so a site not behind a CDN kept answering on plain HTTP indefinitely —
// the certificate was installed and simply not used.

var (
	// The serving block is the one with a document root; redirect-only blocks
	// have none.
	rootDirective  = regexp.MustCompile(`(?m)^\s*root\s+\S+;`)
	listen80       = regexp.MustCompile(`(?m)^[ \t]*listen[ \t]+(\[::\]:)?80[ \t]*;[ \t]*\n`)
	alreadyHasTLS  = regexp.MustCompile(`(?m)^\s*listen\s+(\[::\]:)?443\s+ssl`)
	serverBlockTop = regexp.MustCompile(`(?m)^server\s*\{`)
)

// nginxTLSConfig rewrites a vhost to serve the site over HTTPS and redirect
// HTTP to it.
//
// Returns the configuration unchanged when TLS is already configured, so
// re-issuing a certificate is idempotent.
func nginxTLSConfig(original, domain, certificatePath string, canonical canonicalHost) (string, error) {
	if alreadyHasTLS.MatchString(original) {
		return original, nil
	}

	blocks := splitServerBlocks(original)
	if len(blocks) == 0 {
		return "", fmt.Errorf("no server block was found in the configuration for %s", domain)
	}

	// The canonical host is what HTTP and the non-canonical name both redirect to.
	canonicalName := normaliseHost(domain)
	if _, to, ok := canonicalRedirect(domain, canonical); ok {
		canonicalName = to
	}

	servingIndex := -1
	for index, block := range blocks {
		if rootDirective.MatchString(block) {
			servingIndex = index
			break
		}
	}
	if servingIndex == -1 {
		// A proxied site (Node, container) has no root; fall back to the last
		// block, which is the serving one in every layout this agent generates.
		servingIndex = len(blocks) - 1
	}

	tlsListeners := fmt.Sprintf(
		"\n    listen 443 ssl;\n    listen [::]:443 ssl;\n    ssl_certificate %s/fullchain.pem;\n    ssl_certificate_key %s/privkey.pem;\n",
		certificatePath, certificatePath)

	serving := blocks[servingIndex]
	// Port 80 moves to the redirect block, so the serving block stops answering
	// on plain HTTP entirely.
	serving = listen80.ReplaceAllString(serving, "")
	serving = serverBlockTop.ReplaceAllString(serving, "server {"+tlsListeners)
	blocks[servingIndex] = serving

	// Every name the site answers on is redirected to the canonical host over
	// HTTPS, which covers both the http→https and the www→non-www cases in one
	// block rather than chaining two redirects.
	names := strings.Join(serverNames(domain), " ")
	redirect := fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;
    return 301 https://%s$request_uri;
}

`, names, canonicalName)

	// Existing plain-HTTP redirect blocks are dropped: they would send visitors
	// to http:// and land them back here, and the new block supersedes them.
	remaining := []string{}
	for index, block := range blocks {
		if index != servingIndex && !rootDirective.MatchString(block) && strings.Contains(block, "return 301") {
			continue
		}
		remaining = append(remaining, block)
	}

	return redirect + strings.Join(remaining, "\n"), nil
}

// splitServerBlocks divides a configuration into its top-level `server { … }`
// blocks by counting braces, so a nested `location { … }` does not end a block
// early the way a naive split on "}" would.
func splitServerBlocks(config string) []string {
	blocks := []string{}
	lines := strings.Split(config, "\n")

	current := []string{}
	depth := 0
	inBlock := false

	for _, line := range lines {
		if !inBlock {
			if serverBlockTop.MatchString(line) {
				inBlock = true
				depth = strings.Count(line, "{") - strings.Count(line, "}")
				current = []string{line}
			}
			continue
		}

		current = append(current, line)
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			blocks = append(blocks, strings.Join(current, "\n")+"\n")
			current = nil
			inBlock = false
		}
	}

	// An unterminated block means the file is not something this should rewrite.
	if inBlock {
		return nil
	}
	return blocks
}
