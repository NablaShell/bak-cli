package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

// LockMemory prevents sensitive data from being swapped to disk
func LockMemory(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	
	// mlock the memory region
	ptr := unsafe.Pointer(&data[0])
	_, _, err := syscall.Syscall(syscall.SYS_MLOCK, uintptr(ptr), uintptr(len(data)), 0)
	if err != 0 {
		return err
	}
	
	return nil
}

// UnlockMemory unlocks previously locked memory
func UnlockMemory(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	
	ptr := unsafe.Pointer(&data[0])
	_, _, err := syscall.Syscall(syscall.SYS_MUNLOCK, uintptr(ptr), uintptr(len(data)), 0)
	if err != 0 {
		return err
	}
	
	return nil
}

// Burn securely zeroes memory and prevents compiler optimization
func Burn(data []byte) {
	for i := range data {
		data[i] = 0
	}
	// Prevent compiler from optimizing away the zeroing
	runtime.KeepAlive(data)
}
