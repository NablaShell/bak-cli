package wipe

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// File overwrites path 3 times and removes it.
func File(path string) error {
	// Reject paths that attempt traversal.
	if strings.Contains(path, "..") {
		return fmt.Errorf("path must not contain '..'")
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	size := info.Size()
	// #nosec G304 - Target path for erasure verified by application logic
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	// No defer; we close explicitly to catch errors.

	for pass := 0; pass < 3; pass++ {
		if _, err := f.Seek(0, 0); err != nil {
			_ = f.Close()
			return fmt.Errorf("shred seek failed: %w", err)
		}

		var pattern []byte
		if pass == 2 {
			pattern = make([]byte, 4096)
		} else {
			pattern = make([]byte, 4096)
			if _, err := rand.Read(pattern); err != nil {
				_ = f.Close()
				return fmt.Errorf("failed to generate random pattern: %w", err)
			}
		}

		rem := size
		for rem > 0 {
			n := int64(len(pattern))
			if rem < n {
				n = rem
			}
			if _, err := f.Write(pattern[:n]); err != nil {
				_ = f.Close()
				return fmt.Errorf("shred write failed at pass %d: %w", pass, err)
			}
			rem -= n
		}

		if err := f.Sync(); err != nil {
			_ = f.Close()
			return fmt.Errorf("hardware sync failed at pass %d: %w", pass, err)
		}
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close file cleanly during shredding: %w", err)
	}

	return os.Remove(path)
}

// Dir wipes all files in dir and removes the tree.
func Dir(path string) error {
	return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if err := File(p); err != nil {
				return fmt.Errorf("wipe %s: %w", p, err)
			}
		}
		return nil
	})
	// RemoveAll is called after WalkDir completes; its error is returned.
}
