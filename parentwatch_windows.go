//go:build windows

package main

import (
	"log"
	"os"
	"syscall"
)

// watchParent exits the process when the parent that started it is gone, so a
// supervisor that dies abruptly never leaves a server holding the port. On
// Windows the parent's process handle becomes signalled when it ends.
func watchParent() {
	parent := os.Getppid()
	handle, err := syscall.OpenProcess(syscall.SYNCHRONIZE, false, uint32(parent))
	if err != nil {
		log.Printf("cannot watch parent process %d: %v", parent, err)
		return
	}
	go func() {
		_, _ = syscall.WaitForSingleObject(handle, syscall.INFINITE)
		log.Printf("parent process %d is gone; exiting", parent)
		os.Exit(0)
	}()
}
