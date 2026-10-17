package main

import (
	"errors"
	"path/filepath"

	"github.com/z0orb/watchtower/internal/store"
	"github.com/z0orb/watchtower/internal/winnet"
)

func tuningPath() string { return filepath.Join(store.Dir(), "tuning-backup.json") }

// optimizeAdapter backs up the original settings before changing them; a repeat run keeps the first backup.
func optimizeAdapter(guid string) error {
	backup := map[string]winnet.Tuning{} // adapter GUID -> original settings
	if err := store.Load(tuningPath(), &backup); err != nil {
		return err
	}
	if _, ok := backup[guid]; !ok {
		orig, err := winnet.ReadTuning(guid)
		if err != nil {
			return err
		}
		backup[guid] = orig
		if err := store.Save(tuningPath(), backup); err != nil {
			return err
		}
	}
	return winnet.Optimize(guid)
}

// revertTuning restores every adapter in the backup; failed ones stay in it for a retry.
func revertTuning() error {
	backup := map[string]winnet.Tuning{}
	if err := store.Load(tuningPath(), &backup); err != nil {
		return err
	}
	var errs []error
	for guid, t := range backup {
		if err := winnet.RevertTuning(guid, t); err != nil {
			errs = append(errs, err)
		} else {
			delete(backup, guid)
		}
	}
	if err := store.Save(tuningPath(), backup); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
