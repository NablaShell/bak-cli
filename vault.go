package main

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// Magic separator for metadata integrity
	// Using hex literal without underscores: 0xBAKC0DE = 0xBA, 0xKC, 0xDE (invalid)
	// Actually, let's use a valid hex: 0xBADC0DE (bad code)
	magicSeparator = 0x0BADC0DE
)

// FileEntry represents a file in the vault
type FileEntry struct {
	Path string
	Data []byte
}

// VaultMetadata stores information about the encrypted directory
type VaultMetadata struct {
	DirName string
	Hash    [64]byte // SHA-512
}

// PackDirectory recursively reads all files from a directory
func PackDirectory(root string) ([]FileEntry, string, error) {
	var entries []FileEntry

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path for %s: %w", path, err)
		}

		// Read file contents
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}

		entries = append(entries, FileEntry{
			Path: relPath,
			Data: data,
		})

		return nil
	})

	if err != nil {
		return nil, "", fmt.Errorf("failed to walk directory: %w", err)
	}

	// Sort entries for deterministic output
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})

	// Extract just the directory name (not full path)
	dirName := filepath.Base(root)
	
	return entries, dirName, nil
}

// Serialize converts file entries to binary format with metadata
func Serialize(entries []FileEntry, dirName string) ([]byte, [64]byte) {
	// First serialize just the files payload
	var payload []byte
	for _, entry := range entries {
		// Path length (4 bytes)
		pathLen := uint32(len(entry.Path))
		pathLenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(pathLenBytes, pathLen)
		payload = append(payload, pathLenBytes...)

		// Path
		payload = append(payload, []byte(entry.Path)...)

		// Data size (8 bytes)
		dataSize := uint64(len(entry.Data))
		dataSizeBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(dataSizeBytes, dataSize)
		payload = append(payload, dataSizeBytes...)

		// Data
		payload = append(payload, entry.Data...)
	}

	// Calculate SHA-512 hash of payload
	hash := sha512.Sum512(payload)

	// Build final structure with metadata
	var result []byte
	
	// Directory name length (4 bytes)
	dirNameBytes := []byte(dirName)
	dirNameLen := uint32(len(dirNameBytes))
	dirNameLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(dirNameLenBytes, dirNameLen)
	result = append(result, dirNameLenBytes...)
	
	// Directory name
	result = append(result, dirNameBytes...)
	
	// SHA-512 hash (64 bytes)
	result = append(result, hash[:]...)
	
	// Magic separator (4 bytes)
	magicBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicBytes, magicSeparator)
	result = append(result, magicBytes...)
	
	// Payload
	result = append(result, payload...)

	return result, hash
}

// Deserialize reconstructs file entries and metadata from binary format
func Deserialize(data []byte) ([]FileEntry, *VaultMetadata, error) {
	if len(data) < 4 {
		return nil, nil, errors.New("data too short: missing directory name length")
	}
	
	offset := 0
	
	// Read directory name length
	dirNameLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	
	if offset+int(dirNameLen) > len(data) {
		return nil, nil, errors.New("data too short: truncated directory name")
	}
	
	// Read directory name
	dirName := string(data[offset : offset+int(dirNameLen)])
	offset += int(dirNameLen)
	
	// Read SHA-512 hash
	if offset+64 > len(data) {
		return nil, nil, errors.New("data too short: missing SHA-512 hash")
	}
	
	var hash [64]byte
	copy(hash[:], data[offset:offset+64])
	offset += 64
	
	// Read and verify magic separator
	if offset+4 > len(data) {
		return nil, nil, errors.New("data too short: missing magic separator")
	}
	
	magic := binary.BigEndian.Uint32(data[offset : offset+4])
	if magic != magicSeparator {
		return nil, nil, fmt.Errorf("invalid magic separator: expected 0x%08X, got 0x%08X", magicSeparator, magic)
	}
	offset += 4
	
	// Now read the payload (files)
	payload := data[offset:]
	
	// Verify hash
	calculatedHash := sha512.Sum512(payload)
	if calculatedHash != hash {
		return nil, nil, fmt.Errorf("payload integrity check failed: hash mismatch")
	}
	
	// Parse file entries from payload
	var entries []FileEntry
	payloadOffset := 0
	
	for payloadOffset < len(payload) {
		// Read path length
		if payloadOffset+4 > len(payload) {
			return nil, nil, fmt.Errorf("unexpected end of payload at path length")
		}
		pathLen := binary.BigEndian.Uint32(payload[payloadOffset : payloadOffset+4])
		payloadOffset += 4

		// Read path
		if payloadOffset+int(pathLen) > len(payload) {
			return nil, nil, fmt.Errorf("unexpected end of payload at path")
		}
		path := string(payload[payloadOffset : payloadOffset+int(pathLen)])
		payloadOffset += int(pathLen)

		// Read data size
		if payloadOffset+8 > len(payload) {
			return nil, nil, fmt.Errorf("unexpected end of payload at data size")
		}
		dataSize := binary.BigEndian.Uint64(payload[payloadOffset : payloadOffset+8])
		payloadOffset += 8

		// Read data
		if payloadOffset+int(dataSize) > len(payload) {
			return nil, nil, fmt.Errorf("unexpected end of payload at file data for %s", path)
		}
		fileData := make([]byte, dataSize)
		copy(fileData, payload[payloadOffset:payloadOffset+int(dataSize)])
		payloadOffset += int(dataSize)

		entries = append(entries, FileEntry{
			Path: path,
			Data: fileData,
		})
	}

	metadata := &VaultMetadata{
		DirName: dirName,
		Hash:    hash,
	}

	return entries, metadata, nil
}

// UnpackDirectory recreates directory structure from entries
func UnpackDirectory(entries []FileEntry, root string) error {
	// Create root directory
	if err := os.MkdirAll(root, 0700); err != nil {
		return fmt.Errorf("failed to create root directory %s: %w", root, err)
	}

	for _, entry := range entries {
		fullPath := filepath.Join(root, entry.Path)
		
		// Security check: prevent path traversal
		if !strings.HasPrefix(filepath.Clean(fullPath), filepath.Clean(root)+string(os.PathSeparator)) {
			return fmt.Errorf("path traversal detected in file: %s", entry.Path)
		}
		
		// Create parent directories
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}

		// Write file
		if err := os.WriteFile(fullPath, entry.Data, 0600); err != nil {
			return fmt.Errorf("failed to write file %s: %w", fullPath, err)
		}
	}

	return nil
}

// VerifyVaultIntegrity checks if vault data is intact without decrypting
func VerifyVaultIntegrity(data []byte) error {
	// This is a lightweight check - just verify structure without crypto
	if len(data) < 4 {
		return errors.New("vault too small for directory name length")
	}
	
	dirNameLen := binary.BigEndian.Uint32(data[:4])
	if 4+int(dirNameLen)+64+4 > len(data) {
		return errors.New("vault too small for metadata")
	}
	
	magicOffset := 4 + int(dirNameLen) + 64
	magic := binary.BigEndian.Uint32(data[magicOffset : magicOffset+4])
	if magic != magicSeparator {
		return fmt.Errorf("invalid vault structure: magic separator not found")
	}
	
	return nil
}
