package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/z0orb/watchtower/internal/store"
)

const serviceName = "Watchtower"

const usage = `usage: watchtower <command>
  run      run in this console (admin), logging to the console too
  service  entry point used by the Windows service manager`

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runConsole()
	case "service":
		err = svc.Run(serviceName, handler{})
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchtower:", err)
		os.Exit(1)
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
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("run it from an elevated (Administrator) terminal")
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
