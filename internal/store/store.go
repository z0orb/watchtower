// Package store persists Watchtower's state as JSON files.
package store

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
)

// Load reads path into v. A missing file leaves v unchanged.
func Load(path string, v any) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Save writes v via a temp file and rename, so a crash never leaves a half-written file.
func Save(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
