package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/z0orb/watchtower/internal/store"
	"github.com/z0orb/watchtower/internal/tray"
)

const serviceName = "Watchtower"

// version is set by the release build (-ldflags "-X main.version=0.2.0").
var version = "dev"

const usage = `usage: watchtower <command>
  install    install (or update) the service and tray autostart (admin)
  uninstall  remove them, unpinning the gateway and restoring DNS (admin)
  run      run in this console (admin), logging to the console too
  service  entry point used by the Windows service manager
  tray     notification-area status and alerts (runs as the logged-in user)
Without a command (e.g. double-clicked) it offers to install or update, then opens the tray.`

func main() {
	cmd := "" // no arguments, e.g. double-clicked in Explorer
	if len(os.Args) == 2 {
		cmd = os.Args[1]
	} else if len(os.Args) > 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd {
	case "":
		hideOwnConsole()
		launch()
	case "install":
		err = adminCommand(cmd, install)
	case "uninstall":
		err = adminCommand(cmd, uninstall)
	case "run":
		err = runConsole()
	case "service":
		err = svc.Run(serviceName, handler{})
	case "tray":
		hideOwnConsole()
		tray.Run(filepath.Join(store.Dir(), "watchtower.log"))
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchtower:", err)
		os.Exit(1)
	}
}

var (
	kernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcList = kernel32.NewProc("GetConsoleProcessList")
	procFreeConsole        = kernel32.NewProc("FreeConsole")
)

// ownsConsole reports whether Windows opened a console just for us (Explorer, the Run key, Settings › Apps)
// rather than us running in a terminal.
func ownsConsole() bool {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcList.Call(uintptr(unsafe.Pointer(&pids[0])), 2)
	return n == 1
}

// hideOwnConsole closes the console window Windows opened for us, but keeps a terminal we were started from.
func hideOwnConsole() {
	if ownsConsole() {
		procFreeConsole.Call()
	}
}

func setupLog(console bool) (*slog.Logger, error) {
	if err := store.Init(); err != nil {
		return nil, err
	}
	f, err := openRotating(filepath.Join(store.Dir(), "watchtower.log"), 5<<20, 3)
	if err != nil {
		return nil, err
	}
	var w io.Writer = f
	if console {
		w = io.MultiWriter(f, os.Stderr)
	}
	return slog.New(slog.NewJSONHandler(w, nil)), nil
}

func runConsole() error {
	if err := requireAdmin(); err != nil {
		return err
	}
	log, err := setupLog(true)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runGuard(ctx, log)
}

type handler struct{}

func (handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	log, err := setupLog(false)
	if err != nil {
		return true, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runGuard(ctx, log) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			log.Error("guard stopped", "err", err)
			return true, 1
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}
