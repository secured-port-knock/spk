// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build windows

package server

import (
	"os/exec"
	"strconv"
)

// setProcGroup is a no-op on Windows.
// Windows does not have Unix-style process groups. Process tree management
// is handled by killProcessGroup using taskkill /T.
func setProcGroup(cmd *exec.Cmd) {}

// killProcessGroup terminates the entire process tree rooted at cmd.Process.
// On Windows, Process.Kill() (TerminateProcess) only kills the immediate
// process, NOT its children. For example, "cmd /C ping google.com" spawns
// ping.exe as a child; killing cmd.exe leaves ping.exe running.
// taskkill /T /F /PID kills the process AND all of its descendants.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	// /T = kill process tree, /F = force
	kill := exec.Command("taskkill", "/T", "/F", "/PID", pid)
	_ = kill.Run()
}
