package ipc

import (
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const PipeName = `\\.\pipe\watchtower`

// SYSTEM and Admins full; interactive users read/write; network logons denied.
const pipeSDDL = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// Listen fails if another process already owns the pipe name.
func Listen() (net.Listener, error) {
	return winio.ListenPipe(PipeName, &winio.PipeConfig{SecurityDescriptor: pipeSDDL})
}

var procGetNamedPipeServerSessionId = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeServerSessionId")

// Dial connects only to a pipe served from session 0, where services run, so a program that grabbed the
// pipe name before the service started can't feed the tray fake status.
func Dial(timeout time.Duration) (net.Conn, error) {
	c, err := winio.DialPipe(PipeName, &timeout)
	if err != nil {
		return nil, err
	}
	var session uint32
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		c.Close()
		return nil, errors.New("ipc: can't check the pipe server")
	}
	if r, _, err := procGetNamedPipeServerSessionId.Call(f.Fd(), uintptr(unsafe.Pointer(&session))); r == 0 {
		c.Close()
		return nil, fmt.Errorf("ipc: GetNamedPipeServerSessionId: %w", err)
	}
	if session != 0 {
		c.Close()
		return nil, fmt.Errorf("ipc: pipe server runs in session %d, not as a service", session)
	}
	return c, nil
}
