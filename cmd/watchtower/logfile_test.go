package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.log")
	r, err := openRotating(path, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"aaaaa\n", "bbbbb\n", "ccccc\n", "ddddd\n"} {
		if _, err := r.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	r.f.Close()
	for name, want := range map[string]string{path: "ddddd\n", path + ".1": "ccccc\n", path + ".2": "bbbbb\n"} {
		if b, _ := os.ReadFile(name); string(b) != want {
			t.Errorf("%s = %q, want %q", name, b, want)
		}
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Error("kept more than 3 files")
	}
}
