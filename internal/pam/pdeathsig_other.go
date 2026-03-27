//go:build !linux

package pam

// requestParentDeathSignal is a no-op on non-Linux systems.
// The polling loop's parent-alive check provides the fallback.
func RequestParentDeathSignal() {}
