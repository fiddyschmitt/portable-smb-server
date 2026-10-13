//go:build !windows

package main

import (
	"log"
	"os"
	"time"
)

// watchParent exits the process when the parent that started it is gone, so a
// supervisor that dies abruptly (a crash, a kill -9) never leaves a server
// holding the port. On Unix an orphan is re-parented, so the parent pid
// changes.
func watchParent() {
	parent := os.Getppid()
	go func() {
		for {
			time.Sleep(time.Second)
			if os.Getppid() != parent {
				log.Printf("parent process %d is gone; exiting", parent)
				os.Exit(0)
			}
		}
	}()
}
