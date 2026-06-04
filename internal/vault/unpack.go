package vault

import (
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/NablaShell/bak-cli/internal/compress"
	"github.com/NablaShell/bak-cli/internal/crypto"
	"github.com/NablaShell/bak-cli/internal/progress"
)

// Unpack decrypts a vault and restores files. Memory is bounded by the
// largest single chunk, not the total vault size.
func Unpack(vaultPath string, targetDir string, password []byte) error {
	// Basic sanity check to avoid obvious path traversal when opening the vault file.
	if strings.Contains(vaultPath, "..") {
		return fmt.Errorf("vault path must not contain '..'")
	}
	// #nosec G304 -- vaultPath is a user-supplied file path; this is a CLI tool.
	f, err := os.Open(vaultPath)
	if err != nil {
		return fmt.Errorf("open vault: %w", err)
	}
	defer f.Close()

	vaultInfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat vault: %w", err)
	}
	vaultSize := vaultInfo.Size()

	pr := progress.NewReader(f, vaultSize, "Decrypting")
	defer pr.Finish()

	// Salt.
	salt := make([]byte, crypto.SaltSize)
	if _, err := io.ReadFull(pr, salt); err != nil {
		return fmt.Errorf("salt: %w", err)
	}

	// Key.
	key, err := crypto.DeriveKey(password, salt)
	if err != nil {
		return err
	}
	defer crypto.Burn(key)

	// Decryption.
	cr, err := crypto.NewChunkedReader(pr, key)
	if err != nil {
		return err
	}

	// Decompression.
	dc, err := compress.Decompress(cr)
	if err != nil {
		return fmt.Errorf("decompress: %w", err)
	}
	defer dc.Close()

	return restoreStream(dc, targetDir)
}

// restoreStream reads the header and file entries, writing each file to disk
// without buffering the entire archive. targetDir is the parent directory
// where the vault's root folder will be created.
func restoreStream(r io.Reader, targetDir string) error {
	// Sandbox the output directory to prevent path traversal.
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return fmt.Errorf("create target directory: %w", err)
	}
	root, err := os.OpenRoot(targetDir)
	if err != nil {
		return fmt.Errorf("sandbox target directory: %w", err)
	}
	defer root.Close()

	// Version (2 bytes).
	var buf2 [2]byte
	if _, err := io.ReadFull(r, buf2[:]); err != nil {
		return fmt.Errorf("version: %w", err)
	}
	ver := getUint16(buf2[:])
	if ver != FormatVersion {
		return fmt.Errorf("unsupported version %d", ver)
	}

	// Dir name length (4 bytes).
	var buf4 [4]byte
	if _, err := io.ReadFull(r, buf4[:]); err != nil {
		return fmt.Errorf("dirname length: %w", err)
	}
	nameLen := getUint32(buf4[:])
	if nameLen > MaxDirNameLen {
		return fmt.Errorf("dirname too long: %d", nameLen)
	}

	// Dir name.
	dirBytes := make([]byte, nameLen)
	if _, err := io.ReadFull(r, dirBytes); err != nil {
		return fmt.Errorf("dirname: %w", err)
	}
	dirName := string(dirBytes)
	cleanDir := filepath.Clean(dirName)

	// The vault's root folder must be a simple name, not a path.
	if cleanDir == "." || cleanDir == ".." || filepath.IsAbs(cleanDir) || strings.ContainsRune(cleanDir, filepath.Separator) {
		return fmt.Errorf("invalid root dirname in archive: %s", dirName)
	}

	// Skip hash (64 bytes).
	if _, err := io.CopyN(io.Discard, r, 64); err != nil {
		return fmt.Errorf("hash: %w", err)
	}

	// Magic (4 bytes).
	var magicBuf [4]byte
	if _, err := io.ReadFull(r, magicBuf[:]); err != nil {
		return fmt.Errorf("magic: %w", err)
	}
	if getUint32(magicBuf[:]) != MagicVault {
		return fmt.Errorf("bad magic")
	}

	// Create the vault's root folder inside the sandbox.
	if err := root.MkdirAll(cleanDir, 0700); err != nil {
		return fmt.Errorf("secure mkdir %s: %w", cleanDir, err)
	}

	// Restore files.
	for {
		// Try to read path length. EOF means done.
		if _, err := io.ReadFull(r, buf4[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return fmt.Errorf("path len: %w", err)
		}
		pathLen := getUint32(buf4[:])
		if pathLen == 0 || pathLen > MaxPathLen {
			return fmt.Errorf("bad path length: %d", pathLen)
		}

		// Path.
		pathBytes := make([]byte, pathLen)
		if _, err := io.ReadFull(r, pathBytes); err != nil {
			return fmt.Errorf("path: %w", err)
		}
		filePath := string(pathBytes)

		// Clean and validate the relative path inside the vault.
		cp := filepath.Clean(filePath)
		if filepath.IsAbs(cp) || strings.HasPrefix(cp, "..") || strings.Contains(cp, "..") {
			return fmt.Errorf("path traversal blocked: %s", filePath)
		}

		// Build path relative to the vault root inside the sandbox.
		innerPath := filepath.Join(cleanDir, cp)

		// Create parent directories inside the sandbox.
		dirPart := filepath.Dir(innerPath)
		if dirPart != "." && dirPart != "/" && dirPart != "" {
			if err := root.MkdirAll(dirPart, 0700); err != nil {
				return fmt.Errorf("secure inner mkdir %s: %w", dirPart, err)
			}
		}

		// File size (8 bytes).
		var sizeBuf [8]byte
		if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
			return fmt.Errorf("size: %w", err)
		}
		fileSize := getUint64(sizeBuf[:])
		if fileSize > uint64(MaxFileSize) {
			return fmt.Errorf("file too large: %d", fileSize)
		}
		if fileSize > math.MaxInt64 {
			return fmt.Errorf("file size exceeds system limits: %d", fileSize)
		}

		// Create file inside the sandbox.
		out, err := root.OpenFile(innerPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("sandboxed file creation blocked for %s: %w", innerPath, err)
		}

		_, copyErr := io.CopyN(out, r, int64(fileSize))
		closeErr := out.Close()

		if copyErr != nil {
			return fmt.Errorf("write %s: %w", innerPath, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s: %w", innerPath, closeErr)
		}
	}

	fmt.Printf("\nRestored: %s\n", filepath.Join(targetDir, cleanDir))
	return nil
}
