package main

import (
	"strings"
	"testing"
)

func TestWWWAliasOnlyForRegistrableDomains(t *testing.T) {
	cases := []struct {
		host          string
		expectedAlias string
	}{
		// Registrable: the www name is one people actually type.
		{"example.com", "www.example.com"},
		{"phpflock.com", "www.phpflock.com"},
		{"shadykhan.com", "www.shadykhan.com"},
		{"example.co.uk", "www.example.co.uk"},
		{"example.com.au", "www.example.com.au"},
		{"example.co.in", "www.example.co.in"},

		// Subdomains: nobody visits www.blog.example.com, and asking a CA to
		// validate it guarantees a failure.
		{"blog.example.com", ""},
		{"staging.example.com", ""},
		{"x.phpflock.com", ""},
		{"blog2.phpflock.com", ""},
		{"take.phpflock.com", ""},
		{"deep.sub.example.com", ""},
		{"blog.example.co.uk", ""},

		// Already a www name: must not become www.www.
		{"www.example.com", ""},

		// Not a usable host name at all.
		{"localhost", ""},
		{"com", ""},
	}

	for _, testCase := range cases {
		alias, ok := wwwAliasFor(testCase.host)
		if testCase.expectedAlias == "" {
			if ok {
				t.Errorf("%s: expected no www alias, got %q", testCase.host, alias)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: expected alias %q, got none", testCase.host, testCase.expectedAlias)
			continue
		}
		if alias != testCase.expectedAlias {
			t.Errorf("%s: expected %q, got %q", testCase.host, testCase.expectedAlias, alias)
		}
	}
}

// A public suffix must not be treated as a registrable domain: co.uk is not a
// site somebody owns.
func TestPublicSuffixIsNotRegistrable(t *testing.T) {
	for _, suffix := range []string{"co.uk", "com.au", "com.br"} {
		if isRegistrableDomain(suffix) {
			t.Errorf("%s is a public suffix, not a registrable domain", suffix)
		}
	}
}

func TestServerNamesOrdering(t *testing.T) {
	names := serverNames("example.com")
	if len(names) != 2 || names[0] != "example.com" || names[1] != "www.example.com" {
		t.Errorf("expected the bare name first, got %v", names)
	}

	subdomain := serverNames("blog.example.com")
	if len(subdomain) != 1 || subdomain[0] != "blog.example.com" {
		t.Errorf("a subdomain should serve exactly its own name, got %v", subdomain)
	}
}

func TestServerNamesNormalisesInput(t *testing.T) {
	for _, input := range []string{"Example.COM", " example.com ", "example.com."} {
		names := serverNames(input)
		if names[0] != "example.com" {
			t.Errorf("%q was not normalised, got %q", input, names[0])
		}
	}
}

// The vhost renders as a space-separated list, so this is what actually lands in
// the configuration file.
func TestServerNameDirective(t *testing.T) {
	if joined := strings.Join(serverNames("example.com"), " "); joined != "example.com www.example.com" {
		t.Errorf("unexpected directive: %q", joined)
	}
	if joined := strings.Join(serverNames("blog.example.com"), " "); joined != "blog.example.com" {
		t.Errorf("unexpected directive: %q", joined)
	}
}

func TestCanonicalRedirect(t *testing.T) {
	cases := []struct {
		host       string
		preference canonicalHost
		from, to   string
		expectOK   bool
	}{
		// Default: www redirects to the bare domain.
		{"example.com", canonicalNonWWW, "www.example.com", "example.com", true},
		// Reversed preference.
		{"example.com", canonicalWWW, "example.com", "www.example.com", true},
		// Opted out: serve both, redirect neither.
		{"example.com", canonicalNone, "", "", false},
		// Multi-label TLD behaves like any other registrable domain.
		{"example.co.uk", canonicalNonWWW, "www.example.co.uk", "example.co.uk", true},
		// A subdomain has one name, so there is nothing to redirect.
		{"blog.example.com", canonicalNonWWW, "", "", false},
		{"staging.example.com", canonicalWWW, "", "", false},
	}

	for _, testCase := range cases {
		from, to, ok := canonicalRedirect(testCase.host, testCase.preference)
		if ok != testCase.expectOK {
			t.Errorf("%s/%s: expected ok=%v, got %v", testCase.host, testCase.preference, testCase.expectOK, ok)
			continue
		}
		if ok && (from != testCase.from || to != testCase.to) {
			t.Errorf("%s/%s: expected %s -> %s, got %s -> %s",
				testCase.host, testCase.preference, testCase.from, testCase.to, from, to)
		}
	}
}

// An unrecognised or empty preference must fall back to the documented default
// rather than silently disabling the redirect.
func TestParseCanonicalHostDefaults(t *testing.T) {
	for _, input := range []string{"", "nonsense", "NON-WWW"} {
		if parsed := parseCanonicalHost(input); parsed != canonicalNonWWW {
			t.Errorf("%q should parse to the default, got %q", input, parsed)
		}
	}
	if parseCanonicalHost("www") != canonicalWWW {
		t.Error("www preference was not honoured")
	}
	if parseCanonicalHost("none") != canonicalNone {
		t.Error("none preference was not honoured")
	}
}
