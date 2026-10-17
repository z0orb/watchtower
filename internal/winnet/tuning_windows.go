package winnet

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Network adapters' driver settings live in numbered subkeys of this device class.
const netClass = `SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}`

// pnpNoPowerSave clears "Allow the computer to turn off this device to save power".
const pnpNoPowerSave = 24

// Tuning is an adapter's original settings; nil means the value didn't exist.
type Tuning struct {
	PnPCapabilities *uint32 `json:"pnp_capabilities"`
	EEE             *string `json:"eee"` // Energy-Efficient Ethernet; only changed when the driver has it
}

func adapterKey(guid string, access uint32) (registry.Key, error) {
	class, err := registry.OpenKey(registry.LOCAL_MACHINE, netClass, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return 0, err
	}
	defer class.Close()
	names, err := class.ReadSubKeyNames(-1)
	if err != nil {
		return 0, err
	}
	for _, n := range names {
		k, err := registry.OpenKey(class, n, registry.QUERY_VALUE|access)
		if err != nil {
			continue // e.g. "Properties", which even admins can't open
		}
		if id, _, err := k.GetStringValue("NetCfgInstanceId"); err == nil && strings.EqualFold(id, guid) {
			return k, nil
		}
		k.Close()
	}
	return 0, fmt.Errorf("no driver settings found for adapter %s", guid)
}

func ReadTuning(guid string) (Tuning, error) {
	var t Tuning
	k, err := adapterKey(guid, 0)
	if err != nil {
		return t, err
	}
	defer k.Close()
	if v, _, err := k.GetIntegerValue("PnPCapabilities"); err == nil {
		u := uint32(v)
		t.PnPCapabilities = &u
	}
	if v, _, err := k.GetStringValue("*EEE"); err == nil {
		t.EEE = &v
	}
	return t, nil
}

// Optimize turns off adapter power saving and Energy-Efficient Ethernet.
// They apply when the adapter next restarts; restarting it here could drop a live game session.
func Optimize(guid string) error {
	k, err := adapterKey(guid, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetDWordValue("PnPCapabilities", pnpNoPowerSave); err != nil {
		return err
	}
	if _, _, err := k.GetStringValue("*EEE"); err == nil {
		return k.SetStringValue("*EEE", "0")
	}
	return nil
}

func RevertTuning(guid string, t Tuning) error {
	k, err := adapterKey(guid, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if t.PnPCapabilities == nil {
		err = k.DeleteValue("PnPCapabilities")
		if errors.Is(err, registry.ErrNotExist) {
			err = nil
		}
	} else {
		err = k.SetDWordValue("PnPCapabilities", *t.PnPCapabilities)
	}
	if err == nil && t.EEE != nil {
		err = k.SetStringValue("*EEE", *t.EEE)
	}
	return err
}
