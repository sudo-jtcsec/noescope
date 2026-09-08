package repository

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveInsideRepository(t *testing.T) {
	root := t.TempDir()

	file := filepath.Join(root, "hello.txt")
	if err := os.WriteFile(file, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	repo, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := repo.Resolve("hello.txt")
	if err != nil {
		t.Fatal(err)
	}

	if resolved != file {
		t.Fatalf("expected %q, got %q", file, resolved)
	}
}

func TestRejectAbsolutePath(t *testing.T) {
	repo, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := repo.Resolve("/etc/passwd"); err == nil {
		t.Fatal("expected absolute path to be rejected")
	}
}

func TestRejectTraversal(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Dir(root)

	outside := filepath.Join(parent, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outside)

	repo, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := repo.Resolve("../outside.txt"); err == nil {
		t.Fatal("expected traversal outside repository to be rejected")
	}
}

func TestRejectSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	target := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(target, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(root, "escape")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	repo, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := repo.Resolve("escape"); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}
