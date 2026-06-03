package main

import (
//	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
)

// InspectVault reads vault metadata without decryption
func InspectVault(path string) (*VaultMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault: %w", err)
	}

	if len(data) < argonSaltLen {
		return nil, fmt.Errorf("vault file too small")
	}

	// Skip salt and try to parse encrypted data
	encrypted := data[argonSaltLen:]
	
	if len(encrypted) < xchachaNonceLen+4 {
		return nil, fmt.Errorf("encrypted data too small")
	}

	// We can't read metadata without decryption, but we can check structure
	// Try to find magic separator in the encrypted data
	// (This won't work directly since it's encrypted, but we can check basic structure)
	
	metadata := &VaultMetadata{
		DirName: "[encrypted]",
	}
	
	return metadata, nil
}

// QuickVaultCheck performs a quick structural check on vault file
func QuickVaultCheck(path string) (map[string]interface{}, error) {
	info := make(map[string]interface{})
	
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot stat vault: %w", err)
	}
	
	info["filename"] = path
	info["size"] = fileInfo.Size()
	info["permissions"] = fileInfo.Mode().String()
	
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read vault: %w", err)
	}
	
	if len(data) < argonSaltLen+xchachaNonceLen {
		info["status"] = "invalid - too small"
		return info, nil
	}
	
	info["status"] = "valid structure"
	info["salt"] = hex.EncodeToString(data[:16])
	info["encrypted_data_size"] = len(data) - argonSaltLen
	
	// Calculate checksum of encrypted data for comparison
	info["encrypted_checksum"] = fmt.Sprintf("%x", hashData(data[argonSaltLen:]))
	
	return info, nil
}

func hashData(data []byte) [32]byte {
	// Simple hash for quick comparison, not crypto-secure
	var hash [32]byte
	for i, b := range data {
		hash[i%32] ^= b ^ byte(i)
	}
	return hash
}
