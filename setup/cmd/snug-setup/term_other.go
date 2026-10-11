//go:build !linux

package main

import "os"

// isTerminal reports whether f is a character device, the nearest test the
// standard library offers off Linux.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
