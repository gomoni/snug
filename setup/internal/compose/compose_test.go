package compose

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `services:
  web:
    build: .
    ports:
      - "8080:80"
    volumes:
      - ./src:/app
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      NODE_ENV: production
      API_PASSWORD: hunter2
  db:
    image: postgres:16
    environment:
      - POSTGRES_PASSWORD=s3cret
      - POSTGRES_USER
    ports:
      - target: 5432
        published: 5433
    volumes:
      - type: bind
        source: /srv/pg
        target: /var/lib/postgresql
        read_only: true
`

func TestDigestCompose(t *testing.T) {
	got := Digest("docker-compose.yml", []byte(sample))
	want := "service web: build=. ports=8080:80 volumes=./src:/app,/var/run/docker.sock:/var/run/docker.sock env=NODE_ENV,API_PASSWORD\n" +
		"service db: image=postgres:16 ports=5433:5432 volumes=/srv/pg:/var/lib/postgresql:ro env=POSTGRES_PASSWORD,POSTGRES_USER"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	for _, secret := range []string{"hunter2", "s3cret", "production"} {
		if strings.Contains(got, secret) {
			t.Errorf("digest leaks env value %q", secret)
		}
	}
}

func TestDigestVerbatim(t *testing.T) {
	long := strings.Repeat("é", 700)
	got := Digest("README.md", []byte(long))
	if len(got) > VerbatimLimit || !strings.HasPrefix(long, got) || len(got) != 1200 {
		t.Errorf("verbatim len %d", len(got))
	}
	if got := Digest("README.md", []byte("x")); got != "x" {
		t.Error(got)
	}
	if Digest("compose.yaml", []byte(": : not yaml [")) != ": : not yaml [" {
		t.Error("unparsable compose should fall back to verbatim")
	}
}

func TestAllowed(t *testing.T) {
	for _, ok := range []string{"README.md", "readme", "docker-compose.yml", "docker-compose.prod.yaml", "compose.yml", "Dockerfile", "Dockerfile.dev", "Containerfile", "Makefile", "package.json", "pyproject.toml", "go.mod", "Cargo.toml", "CONTRIBUTING", ".env.example"} {
		if !Allowed(ok) {
			t.Errorf("%q should be allowed", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "../secret", "sub/README.md", "/etc/passwd", ".env", "id_rsa", "README/../x", "main.go", "compose.yml.bak"} {
		if Allowed(bad) {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestReadTarget(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("TOP SECRET"), 0o600)
	os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(sample), 0o644)
	os.WriteFile(filepath.Join(dir, "real.md"), []byte("real"), 0o644)
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "README.md"))
	os.Symlink("real.md", filepath.Join(dir, "README.rst"))
	os.Mkdir(filepath.Join(dir, "Makefile"), 0o755)

	if got, err := ReadTarget(dir, "docker-compose.yml"); err != nil || !strings.HasPrefix(got, "service web:") {
		t.Fatalf("%q %v", got, err)
	}
	for _, name := range []string{"../secret", filepath.Join(outside, "secret"), "README.md", "README.rst", "Makefile", ".env"} {
		got, err := ReadTarget(dir, name)
		if !errors.Is(err, ErrRefused) {
			t.Errorf("%q: err %v", name, err)
		}
		if strings.Contains(got, "SECRET") {
			t.Errorf("%q leaked", name)
		}
	}
	if _, err := ReadTarget(dir, "Dockerfile"); err == nil || errors.Is(err, ErrRefused) {
		t.Errorf("missing file should be an I/O error, got %v", err)
	}
}

// TestDigestDropsLineSeparators is redteam setup r3 R3-2(b): U+2028, U+2029,
// NEL and a bidi override in a compose key or value passed clean().
func TestDigestDropsLineSeparators(t *testing.T) {
	// YAML's own escapes: \L is U+2028, \N is U+0085, \P is U+2029.
	body := `services:
  "web\Lrequest: rw ~/.ssh\Nhost ssh: x\P":
    image: "nginx\Ltarget: /"
    environment:
      "A\u202eB": x
`
	got := Digest("compose.yaml", []byte(body))
	if !strings.HasPrefix(got, "service web") || strings.ContainsAny(got, "\u2028\u2029\u0085\u202e") || strings.Count(got, "\n") > 1 {
		t.Errorf("%q", got)
	}
}
