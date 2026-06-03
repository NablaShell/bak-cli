package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// Number of overwrite passes
	wipePasses = 3
)

// WipeFile securely deletes a file by overwriting before removal
func WipeFile(path string) error {
	// Get file info
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat file %s: %w", path, err)
	}

	size := info.Size()
	
	// Open file for writing
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file for wiping %s: %w", path, err)
	}
	defer file.Close()

	// Multiple overwrite passes
	for pass := 0; pass < wipePasses; pass++ {
		// Seek to beginning
		if _, err := file.Seek(0, 0); err != nil {
			return fmt.Errorf("failed to seek file %s: %w", path, err)
		}

		// Generate random data or zeros
		var pattern []byte
		if pass == wipePasses-1 {
			// Last pass: zeros
			pattern = make([]byte, 4096) // Already zeroed
		} else {
			// Random data
			pattern = make([]byte, 4096)
			if _, err := rand.Read(pattern); err != nil {
				return fmt.Errorf("failed to generate random data: %w", err)
			}
		}

		// Overwrite file in chunks
		remaining := size
		for remaining > 0 {
			chunkSize := int64(len(pattern))
			if remaining < chunkSize {
				chunkSize = remaining
			}
			
			if _, err := file.Write(pattern[:chunkSize]); err != nil {
				return fmt.Errorf("failed to write pattern to %s: %w", path, err)
			}
			
			remaining -= chunkSize
		}

		// Ensure data is flushed to disk
		if err := file.Sync(); err != nil {
			return fmt.Errorf("failed to sync file %s: %w", path, err)
		}
	}

	// Close file before removal
	file.Close()

	// Remove the file
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove file %s: %w", path, err)
	}

	return nil
}

// WipeDirectory securely deletes an entire directory
func WipeDirectory(path string) error {
	// First pass: wipe all files
	err := filepath.WalkDir(path, func(filePath string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		if !d.IsDir() {
			if err := WipeFile(filePath); err != nil {
				return fmt.Errorf("failed to wipe file %s: %w", filePath, err)
			}
		}
		
		return nil
	})
	
	if err != nil {
		return fmt.Errorf("failed to wipe directory contents: %w", err)
	}

	// Second pass: remove empty directories
	err = filepath.WalkDir(path, func(dirPath string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		if d.IsDir() {
			// We'll handle directory removal in the main function
			// after this walk completes
		}
		
		return nil
	})
	
	if err != nil {
		return err
	}

	// Remove the root directory and all empty subdirectories
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("failed to remove directory %s: %w", path, err)
	}

	return nil
}
