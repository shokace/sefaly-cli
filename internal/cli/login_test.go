package cli

import "testing"

func TestValidVerificationURL(t *testing.T) {
	const prod = "https://www.sefaly.com"
	cases := []struct {
		name, raw, base string
		ok              bool
	}{
		// The real-world case: prod API base is www, server returns apex.
		{"apex from www base", "https://sefaly.com/cli-auth?user_code=HHF7-6H6V", prod, true},
		{"www from www base", "https://www.sefaly.com/cli-auth?user_code=X", prod, true},
		{"subdomain of base", "https://auth.sefaly.com/cli-auth", prod, true},
		{"apex base accepts www", "https://www.sefaly.com/cli-auth", "https://sefaly.com", true},
		{"loopback dev", "http://localhost:3000/cli-auth", "http://localhost:3000", true},

		{"off-origin host", "https://evil.com/cli-auth?user_code=X", prod, false},
		{"lookalike suffix", "https://notsefaly.com/cli-auth", prod, false},
		{"subdomain spoof", "https://sefaly.com.evil.com/cli-auth", prod, false},
		{"http downgrade on prod", "http://sefaly.com/cli-auth", prod, false},
		{"non-http scheme", "file:///etc/passwd", prod, false},
		{"garbage", "::not a url::", prod, false},
	}
	for _, c := range cases {
		got := validVerificationURL(c.raw, c.base)
		accepted := got != ""
		if accepted != c.ok {
			t.Errorf("%s: validVerificationURL(%q, %q) accepted=%v, want %v", c.name, c.raw, c.base, accepted, c.ok)
		}
		if c.ok && got != c.raw {
			t.Errorf("%s: expected the URL returned verbatim, got %q", c.name, got)
		}
	}
}
