package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/prusa3d/prusa-connect/internal/upgrade"
)

// backupCreatePostgresConfig is a configuration whose host database is
// PostgreSQL. The DSN is never dialled: fakePostgresTools stands in for psql
// and pg_dump.
func backupCreatePostgresConfig(t *testing.T, postgresBackup string) string {
	t.Helper()

	root := t.TempDir()
	configPath := filepath.Join(root, "config", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}

	content := "persistence:\n" +
		"  type: postgres\n" +
		"  postgres:\n" +
		"    dsn: \"postgres://connect:secret@127.0.0.1:1/connect?sslmode=disable\"\n"
	if postgresBackup != "" {
		content += "core:\n  upgrade:\n    postgres_backup: " + postgresBackup + "\n"
	}
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return configPath
}

// fakePostgresTools puts a psql that accepts every check and a pg_dump that
// writes a fixed dump first on PATH. The test using it cannot run in parallel.
func fakePostgresTools(t *testing.T) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("the PostgreSQL tools are shell scripts")
	}

	bin := t.TempDir()
	scripts := map[string]string{
		"psql": "#!/bin/sh\nexit 0\n",
		"pg_dump": "#!/bin/sh\nfor arg in \"$@\"; do\n" +
			"  case \"$arg\" in --file=*) printf 'fake dump' > \"${arg#--file=}\" ;; esac\n" +
			"done\n",
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestBackupCreateTakesThePostgresModeFromTheConfig(t *testing.T) {
	cases := []struct {
		name     string
		config   string
		args     []string
		wantMode upgrade.PostgresMode
		wantDump bool
	}{
		{name: "the config names pg_dump", config: "pg_dump", wantMode: upgrade.PostgresDump, wantDump: true},
		{
			name: "the flag wins over the config", config: "pg_dump",
			args:     []string{"-postgres", "external", "-acknowledge-external-postgres"},
			wantMode: upgrade.PostgresExternal,
		},
		{
			name: "the config names external", config: "external",
			args: []string{"-acknowledge-external-postgres"}, wantMode: upgrade.PostgresExternal,
		},
		{
			name: "nothing is set", args: []string{"-acknowledge-external-postgres"},
			wantMode: upgrade.PostgresExternal,
		},
		{
			name: "the flag names pg_dump", args: []string{"-postgres", "pg_dump"},
			wantMode: upgrade.PostgresDump, wantDump: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakePostgresTools(t)
			configPath := backupCreatePostgresConfig(t, tc.config)
			backups := filepath.Join(t.TempDir(), "backups")

			var out bytes.Buffer
			args := append([]string{"create", "-config", configPath, "-to", backups, "-json"}, tc.args...)
			if err := Backup(t.Context(), &out, args); err != nil {
				t.Fatal(err)
			}

			var manifest upgrade.BackupManifest
			if err := json.Unmarshal(out.Bytes(), &manifest); err != nil {
				t.Fatalf("manifest %q: %v", out.String(), err)
			}
			if len(manifest.Postgres) != 1 {
				t.Fatalf("PostgreSQL entries are %#v", manifest.Postgres)
			}

			entry := manifest.Postgres[0]
			if entry.Name != "host" || entry.Mode != tc.wantMode {
				t.Fatalf("entry is %#v, want host with mode %s", entry, tc.wantMode)
			}
			if got := entry.Path != ""; got != tc.wantDump {
				t.Fatalf("entry %#v has a dump: %v, want %v", entry, got, tc.wantDump)
			}
			if tc.wantDump {
				content, err := os.ReadFile(filepath.Join(backups, manifest.ID, entry.Path))
				if err != nil || string(content) != "fake dump" {
					t.Fatalf("dump is %q, %v", content, err)
				}
			}
		})
	}
}

func TestBackupCreateNamesTheWaysPastAnUnacknowledgedPostgres(t *testing.T) {
	t.Parallel()

	for _, configured := range []string{"", "external", "none"} {
		name := configured
		if name == "" {
			name = "unset"
		}
		t.Run("config "+name, func(t *testing.T) {
			t.Parallel()

			configPath := backupCreatePostgresConfig(t, configured)
			backups := filepath.Join(t.TempDir(), "backups")

			err := Backup(t.Context(), &bytes.Buffer{}, []string{"create", "-config", configPath, "-to", backups})
			if !errors.Is(err, upgrade.ErrPostgresUnconfirmed) {
				t.Fatalf("error is %v, want %v", err, upgrade.ErrPostgresUnconfirmed)
			}
			if errors.Is(err, ErrUsage) {
				t.Fatalf("error %v is a usage error", err)
			}

			for _, want := range []string{
				"-postgres pg_dump", "core.upgrade.postgres_backup: pg_dump", "-acknowledge-external-postgres",
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not name %q", err, want)
				}
			}

			if ids, listErr := backupIDs(backups); listErr == nil && len(ids) != 0 {
				t.Fatalf("a refused backup left %v", ids)
			}
		})
	}
}
