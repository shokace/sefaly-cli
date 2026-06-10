package cli

import "testing"

func TestUniqueFileName(t *testing.T) {
	taken := func(names ...string) map[string]string {
		m := map[string]string{}
		for _, n := range names {
			m[n] = "id"
		}
		return m
	}
	cases := []struct {
		name    string
		desired string
		taken   map[string]string
		want    string
	}{
		{"no collision", "report.pdf", taken(), "report.pdf"},
		{"one collision", "report.pdf", taken("report.pdf"), "report (1).pdf"},
		{"two collisions", "report.pdf", taken("report.pdf", "report (1).pdf"), "report (2).pdf"},
		{"gap reuse", "report.pdf", taken("report.pdf", "report (2).pdf"), "report (1).pdf"},
		{"no extension", "README", taken("README"), "README (1)"},
		{"dotfile", ".env", taken(".env"), ".env (1)"},
		{"multi-dot ext", "archive.tar.gz", taken("archive.tar.gz"), "archive.tar (1).gz"},
	}
	for _, c := range cases {
		if got := uniqueFileName(c.desired, c.taken); got != c.want {
			t.Errorf("%s: uniqueFileName(%q) = %q, want %q", c.name, c.desired, got, c.want)
		}
	}
}
