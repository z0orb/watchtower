package store

import (
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	var got map[string]string
	if err := Load(path, &got); err != nil || got != nil {
		t.Fatalf("missing file: got %v, %v", got, err)
	}
	want := map[string]string{"home|192.168.1.1": "aa:bb:cc:00:00:01"}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, want); err != nil { // overwrite an existing file
		t.Fatal(err)
	}
	if err := Load(path, &got); err != nil || got["home|192.168.1.1"] != want["home|192.168.1.1"] {
		t.Fatalf("got %v, %v", got, err)
	}
}
