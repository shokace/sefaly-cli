package cli

import (
	"reflect"
	"testing"
)

func TestTokenize(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"ls", []string{"ls"}},
		{"  mv   a    b  ", []string{"mv", "a", "b"}},
		{`cd "New Folder"`, []string{"cd", "New Folder"}},
		{`get 'my file.txt' /tmp/out`, []string{"get", "my file.txt", "/tmp/out"}},
		{`share "a b" --to x`, []string{"share", "a b", "--to", "x"}},
		{"", nil},
	}
	for _, c := range cases {
		if got := tokenize(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("tokenize(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestShellAbs(t *testing.T) {
	s := &shellSession{cwdPath: "/Photos/2026"}
	cases := []struct {
		arg, want string
	}{
		{"file.txt", "Photos/2026/file.txt"}, // relative
		{"/top.txt", "top.txt"},              // absolute
		{"sub/y", "Photos/2026/sub/y"},       // nested relative
		{"../x", "Photos/x"},                 // parent
		{"..", "Photos"},                     // bare parent
		{".", "Photos/2026"},                 // current
	}
	for _, c := range cases {
		if got := s.abs(c.arg); got != c.want {
			t.Errorf("abs(%q) from %q = %q, want %q", c.arg, s.cwdPath, got, c.want)
		}
	}
}

func TestShellAbsFromRoot(t *testing.T) {
	s := &shellSession{cwdPath: "/"}
	if got := s.abs("Photos"); got != "Photos" {
		t.Errorf("abs(Photos) from / = %q, want Photos", got)
	}
	if got := s.abs("/"); got != "" {
		t.Errorf("abs(/) = %q, want empty (root)", got)
	}
}
