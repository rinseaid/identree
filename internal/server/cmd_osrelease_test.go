package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadOSReleasePretty(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "ubuntu",
			content: `PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
`,
			want: "Ubuntu 24.04.4 LTS",
		},
		{
			name: "rocky",
			content: `NAME="Rocky Linux"
VERSION="9.3 (Blue Onyx)"
ID="rocky"
PRETTY_NAME="Rocky Linux 9.3 (Blue Onyx)"
VERSION_ID="9.3"
`,
			want: "Rocky Linux 9.3 (Blue Onyx)",
		},
		{
			name: "debian-no-pretty",
			content: `NAME="Debian GNU/Linux"
VERSION_ID="12"
`,
			want: "Debian GNU/Linux 12",
		},
		{
			name: "name-only",
			content: `NAME="Alpine Linux"
`,
			want: "Alpine Linux",
		},
		{
			name: "with-comments-and-blanks",
			content: `# os-release for the test rig

PRETTY_NAME='Fedora Linux 41 (Workstation Edition)'
`,
			want: "Fedora Linux 41 (Workstation Edition)",
		},
		{
			name:    "empty",
			content: ``,
			want:    "",
		},
	}

	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".release")
			if err := os.WriteFile(path, []byte(tc.content), 0644); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := readOSReleasePretty(path)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}

	// Missing file returns empty.
	if got := readOSReleasePretty(filepath.Join(dir, "does-not-exist")); got != "" {
		t.Errorf("missing file: got %q, want empty", got)
	}
}

func TestDetectOSInfo_FallbackContainsArch(t *testing.T) {
	got := detectOSInfo()
	if got == "" {
		t.Error("detectOSInfo returned empty")
	}
	// Whatever the result, it must mention the running architecture so the
	// dashboard renders a useful value on every supported platform.
	if !contains(got, "amd64") && !contains(got, "arm64") && !contains(got, "386") && !contains(got, "arm") {
		t.Errorf("detectOSInfo missing arch token: %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
