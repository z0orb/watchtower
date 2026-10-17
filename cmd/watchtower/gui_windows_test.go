package main

import (
	"testing"
	"unsafe"
)

func TestShellExecuteInfoSize(t *testing.T) {
	if n := unsafe.Sizeof(shellExecuteInfo{}); n != 112 { // sizeof(SHELLEXECUTEINFOW) on amd64
		t.Fatalf("size %d, want 112", n)
	}
}
