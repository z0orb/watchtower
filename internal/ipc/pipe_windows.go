package ipc

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

const PipeName = `\\.\pipe\watchtower`

// SYSTEM and Admins full; interactive users read/write; network logons denied.
const pipeSDDL = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// Listen fails if another process already owns the pipe name.
func Listen() (net.Listener, error) {
	return winio.ListenPipe(PipeName, &winio.PipeConfig{SecurityDescriptor: pipeSDDL})
}

// shortcut: the tray doesn't verify the pipe server is the SYSTEM service, so a squatter started before
// the service could feed it fake status; check GetNamedPipeServerProcessId's owner if that matters.
func Dial(timeout time.Duration) (net.Conn, error) { return winio.DialPipe(PipeName, &timeout) }
