// Copyright (c) 2024-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// SPDX-License-Identifier: MIT

//go:build !windows

package server

import (
	"os/exec"
	"syscall"
)

// setProcGroup places the command in its own process group so that
// killProcessGroup can send a signal to the entire tree.
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup sends SIGKILL to the process group led by cmd.Process.
// Because Setpgid was set, the PGID equals the PID of the child.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		// Negative PID targets the entire process group.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
