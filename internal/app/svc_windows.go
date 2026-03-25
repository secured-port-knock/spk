//go:build windows

// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

package app

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
)

// spkWindowsService implements golang.org/x/sys/windows/svc.Handler.
// It runs the server function in a goroutine and forwards SCM control requests.
type spkWindowsService struct {
	run  func()
	stop func()
}

func (ws *spkWindowsService) Execute(
	_ []string,
	req <-chan svc.ChangeRequest,
	status chan<- svc.Status,
) (svcSpecificEC bool, exitCode uint32) {
	// Acknowledge that we are starting.
	status <- svc.Status{State: svc.StartPending}

	// Launch the server in a goroutine; done is closed when it returns.
	done := make(chan struct{})
	go func() {
		defer close(done)
		ws.run()
	}()

	// Tell the SCM we are running -- this clears the ERROR 1053 timer.
	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				if ws.stop != nil {
					ws.stop()
				}
				// Wait for Run() to finish cleanup (flush logs, close ports)
				// before telling the SCM we are stopped. Without this wait,
				// the process exits immediately, causing Error 109 "pipe ended"
				// and empty log files (deferred Close never runs).
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return false, 0
			case svc.Interrogate:
				status <- c.CurrentStatus
			}
		case <-done:
			// Server exited on its own.
			return false, 0
		}
	}
}

// runAsWindowsService checks whether the process was launched by the Windows
// Service Control Manager.  If yes it registers the service handler and blocks
// until the service stops, returning (true, nil) on clean exit.
// Returns (false, nil) when running interactively (not as a service).
func runAsWindowsService(svcName string, runFn func(), stopFn func()) (ran bool, err error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false, fmt.Errorf("detect windows service: %w", err)
	}
	if !isService {
		return false, nil
	}

	if svcName == "" {
		svcName = "spk"
	}

	ws := &spkWindowsService{run: runFn, stop: stopFn}
	if err := svc.Run(svcName, ws); err != nil {
		fmt.Fprintf(os.Stderr, "Windows service error: %v\n", err)
		return true, err
	}
	return true, nil
}
