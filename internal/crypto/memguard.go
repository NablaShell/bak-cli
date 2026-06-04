package crypto

import (
	"runtime"
	"syscall"
)

// Burn zeroes a byte slice. The KeepAlive prevents the compiler from
// optimizing away the zeroing.
func Burn(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// Lock calls mlock to prevent a slice from being swapped to disk.
func Lock(b []byte) error {
	return syscall.Mlock(b)
}

// Unlock calls munlock.
func Unlock(b []byte) error {
	return syscall.Munlock(b)
}
