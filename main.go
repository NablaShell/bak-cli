package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/term"
)

const (
	vaultFileName = "vault.bak"
)

var (
	// Flags
	lockFlag    = flag.String("lock", "", "Directory to lock/seal")
	unlockFlag  = flag.String("unlock", "", "Vault file to unlock")
	duressFlag  = flag.String("duress", "", "Duress password (triggers secure deletion)")
	outputFlag  = flag.String("output", "", "Output file for vault (default: vault.bak in current dir)")
	verboseFlag = flag.Bool("verbose", false, "Verbose output")
)

func main() {
	flag.Parse()

	// Validate arguments
	if *lockFlag != "" && *unlockFlag != "" {
		fmt.Fprintln(os.Stderr, "Error: cannot use both --lock and --unlock simultaneously")
		os.Exit(1)
	}

	if *lockFlag == "" && *unlockFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: must specify either --lock or --unlock")
		flag.Usage()
		os.Exit(1)
	}

	var err error
	if *lockFlag != "" {
		err = handleLock(*lockFlag)
	} else {
		err = handleUnlock(*unlockFlag)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func handleLock(dir string) error {
	// Validate directory exists
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("cannot access directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}

	// Get absolute path for better directory name extraction
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Get password
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()

	// Confirm password
	fmt.Print("Confirm password: ")
	confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password confirmation: %w", err)
	}
	fmt.Println()

	if string(password) != string(confirmPassword) {
		Burn(password)
		Burn(confirmPassword)
		return errors.New("passwords do not match")
	}

	// Secure password memory
	if err := LockMemory(password); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to lock memory: %v\n", err)
	}
	defer func() {
		UnlockMemory(password)
		Burn(password)
	}()

	defer Burn(confirmPassword)

	// Pack directory
	if *verboseFlag {
		fmt.Printf("Packing directory: %s\n", absDir)
	}
	entries, dirName, err := PackDirectory(absDir)
	if err != nil {
		return err
	}
	
	if *verboseFlag {
		fmt.Printf("Found %d files in '%s'\n", len(entries), dirName)
	}

	// Serialize entries with metadata
	payload, hashSum := Serialize(entries, dirName)
	
	if *verboseFlag {
		fmt.Printf("Payload size: %d bytes\n", len(payload))
		fmt.Printf("SHA-512: %x\n", hashSum)
	}

	// Generate salt and derive key
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	key, err := DeriveKey(password, salt)
	if err != nil {
		return err
	}
	defer Burn(key)

	// Encrypt payload
	encrypted, err := Encrypt(payload, key)
	if err != nil {
		return err
	}

	// Construct vault file
	vault := make([]byte, 0, argonSaltLen+len(encrypted))
	vault = append(vault, salt...)
	vault = append(vault, encrypted...)

	// Write vault file
	outputPath := *outputFlag
	if outputPath == "" {
		outputPath = vaultFileName
	}

	if *verboseFlag {
		fmt.Printf("Writing vault to: %s\n", outputPath)
	}
	if err := os.WriteFile(outputPath, vault, 0600); err != nil {
		return fmt.Errorf("failed to write vault file: %w", err)
	}

	// Securely delete original directory
	if *verboseFlag {
		fmt.Printf("Securely deleting original directory: %s\n", absDir)
	}
	if err := WipeDirectory(absDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to securely delete directory: %v\n", err)
		fmt.Fprintf(os.Stderr, "Directory may not have been fully wiped. Manual cleanup required.\n")
		return fmt.Errorf("secure deletion failed: %w", err)
	}

	fmt.Printf("Directory '%s' successfully locked and secured.\n", dirName)
	if *verboseFlag {
		fmt.Printf("Vault file: %s\n", outputPath)
	}
	return nil
}

func handleUnlock(vaultPath string) error {
	// Read vault file
	vault, err := os.ReadFile(vaultPath)
	if err != nil {
		return fmt.Errorf("cannot read vault file %s: %w", vaultPath, err)
	}

	// Validate vault size
	if len(vault) < argonSaltLen+xchachaNonceLen {
		return errors.New("invalid vault file: too small")
	}

	// Extract salt and encrypted data
	salt := vault[:argonSaltLen]
	encrypted := vault[argonSaltLen:]

	// Get password
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()

	// Secure password memory
	if err := LockMemory(password); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to lock memory: %v\n", err)
	}
	defer func() {
		UnlockMemory(password)
		Burn(password)
	}()

	// Check for duress password
	if *duressFlag != "" && string(password) == *duressFlag {
		fmt.Println("⚠️  Duress password detected! Securely deleting vault...")
		if err := WipeFile(vaultPath); err != nil {
			return fmt.Errorf("failed to securely delete vault: %w", err)
		}
		fmt.Println("Vault successfully destroyed.")
		os.Exit(0)
		return nil
	}

	// Derive key
	key, err := DeriveKey(password, salt)
	if err != nil {
		return err
	}
	defer Burn(key)

	// Decrypt
	payload, err := Decrypt(encrypted, key)
	if err != nil {
		// Authentication failed - likely wrong password
		fmt.Fprintln(os.Stderr, "❌ Authentication failed: incorrect password or corrupted vault")
		os.Exit(1)
		return nil
	}

	// Deserialize entries with metadata
	entries, metadata, err := Deserialize(payload)
	if err != nil {
		return fmt.Errorf("failed to deserialize vault contents: %w", err)
	}

	if *verboseFlag {
		fmt.Printf("Vault contents: %d files\n", len(entries))
		fmt.Printf("Original directory: %s\n", metadata.DirName)
		fmt.Printf("Integrity hash: %x\n", metadata.Hash)
	}

	// Create output directory using original name
	outputDir := metadata.DirName
	
	// Check if directory already exists
	if _, err := os.Stat(outputDir); err == nil {
		fmt.Printf("⚠️  Directory '%s' already exists. ", outputDir)
		fmt.Print("Overwrite? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			return fmt.Errorf("restore cancelled by user")
		}
		// Remove existing directory
		if err := os.RemoveAll(outputDir); err != nil {
			return fmt.Errorf("failed to remove existing directory: %w", err)
		}
	}

	if *verboseFlag {
		fmt.Printf("Restoring %d files to: %s\n", len(entries), outputDir)
	}
	
	if err := UnpackDirectory(entries, outputDir); err != nil {
		return err
	}

	fmt.Printf("✅ Vault successfully unlocked and restored to '%s'\n", outputDir)
	return nil
}
