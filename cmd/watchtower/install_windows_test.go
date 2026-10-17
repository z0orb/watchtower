package main

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestServiceSDDL(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(serviceSDDL)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	iu, _ := windows.CreateWellKnownSid(windows.WinInteractiveSid)
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(iu) {
			continue
		}
		if ace.Mask&windows.SERVICE_START == 0 || ace.Mask&(windows.SERVICE_STOP|windows.SERVICE_CHANGE_CONFIG|windows.DELETE|windows.WRITE_DAC) != 0 {
			t.Fatalf("interactive users mask %#x: want start, not stop/config/delete/dac", ace.Mask)
		}
		return
	}
	t.Fatal("no ACE for interactive users")
}
