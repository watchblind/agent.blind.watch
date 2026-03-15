//go:build linux

package main

import "syscall"

func init() {
	// Disable core dumps to prevent DEK from being written to disk
	var rlimit syscall.Rlimit
	syscall.Setrlimit(syscall.RLIMIT_CORE, &rlimit) // {Cur: 0, Max: 0}
}
