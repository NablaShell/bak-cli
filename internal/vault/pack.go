package vault

import (
	"crypto/sha512"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/NablaShell/bak-cli/internal/compress"
	"github.com/NablaShell/bak-cli/internal/crypto"
	"github.com/NablaShell/bak-cli/internal/progress"
)

type FileEntry struct {
	Path string
	Size int64
}

// Scan walks root (sandboxed via os.Root) and collects relative file paths.
func Scan(root *os.Root) ([]FileEntry, string, error) {
	var entries []FileEntry
	dirName := root.Name() // base name of the sandboxed directory

	err := filepath.WalkDir(root.Name(), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root.Name(), path)
		if err != nil {
			return err
		}
		entries = append(entries, FileEntry{Path: rel, Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("walk: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, dirName, nil
}

// Pack encrypts a directory into a vault file.
func Pack(dir, output string, password []byte, chunkSize int) error {
	// Open the source directory inside a sandbox (prevents path traversal during read).
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open source directory: %w", err)
	}
	defer root.Close()

	entries, dirName, err := Scan(root)
	if err != nil {
		return err
	}

	// ---- metadata validation ----
	if len(dirName) > math.MaxUint32 {
		return fmt.Errorf("directory name too long: exceeds max uint32")
	}
	requiredMetaLen := 2 + 4 + len(dirName) + 64 + 4
	if requiredMetaLen > 1024 {
		return fmt.Errorf("directory name %q too long for metadata buffer", dirName)
	}

	// Total payload size.
	var totalPayload int64 = int64(requiredMetaLen)
	for _, e := range entries {
		if len(e.Path) > math.MaxUint32 {
			return fmt.Errorf("file path too long: %s", e.Path)
		}
		totalPayload += 4 + int64(len(e.Path)) + 8 + e.Size
	}

	// ---- build metadata header ----
	var meta [1024]byte
	off := 0
	putUint16(meta[off:], FormatVersion)
	off += 2
	// #nosec G115 - Checked above in validation block
	putUint32(meta[off:], uint32(len(dirName))) // safe: checked above
	off += 4
	copy(meta[off:], dirName)
	off += len(dirName)
	hashOff := off
	off += 64
	putUint32(meta[off:], MagicVault)
	off += 4
	metaLen := off

	// #nosec G304 - Output vault path is explicitly provided by the user via command line
	out, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	// Salt.
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}
	if _, err := out.Write(salt); err != nil {
		return fmt.Errorf("write salt: %w", err)
	}

	// Key.
	key, err := crypto.DeriveKey(password, salt)
	if err != nil {
		return err
	}
	defer crypto.Burn(key)

	// Encryption.
	cw, err := crypto.NewChunkedWriter(out, key, chunkSize)
	if err != nil {
		return err
	}

	// Compression.
	comp, err := compress.Compress(cw)
	if err != nil {
		return err
	}

	// Progress wrapper.
	pcomp := progress.NewWriter(comp, totalPayload, "Packing")
	defer pcomp.Finish()

	// SHA-512 hasher.
	hasher := sha512.New()

	// ---- write metadata ----
	if _, err := pcomp.Write(meta[:metaLen]); err != nil {
		return fmt.Errorf("write metadata to compressor: %w", err)
	}
	if _, err := hasher.Write(meta[:metaLen]); err != nil {
		return fmt.Errorf("write metadata to hasher: %w", err)
	}

	// ---- write files ----
	for _, e := range entries {
		var buf [12]byte

		// path length
		if len(e.Path) > math.MaxUint32 { // belt-and-suspenders
			return fmt.Errorf("file path too long: %s", e.Path)
		}
		// #nosec G115 - Checked above against math.MaxUint32
		putUint32(buf[0:], uint32(len(e.Path)))
		if _, err := pcomp.Write(buf[:4]); err != nil {
			return fmt.Errorf("write path len: %w", err)
		}
		if _, err := hasher.Write(buf[:4]); err != nil {
			return fmt.Errorf("hash path len: %w", err)
		}

		// path
		if _, err := pcomp.Write([]byte(e.Path)); err != nil {
			return fmt.Errorf("write path: %w", err)
		}
		if _, err := hasher.Write([]byte(e.Path)); err != nil {
			return fmt.Errorf("hash path: %w", err)
		}

		// file size
		if e.Size < 0 {
			return fmt.Errorf("negative file size for %s: %d", e.Path, e.Size)
		}
		// #nosec G115 -- Size is guaranteed >= 0 by the check above
		putUint64(buf[0:], uint64(e.Size))
		if _, err := pcomp.Write(buf[:8]); err != nil {
			return fmt.Errorf("write file size: %w", err)
		}
		if _, err := hasher.Write(buf[:8]); err != nil {
			return fmt.Errorf("hash file size: %w", err)
		}

		// Open file safely inside the sandbox.
		f, err := root.Open(e.Path)
		if err != nil {
			return fmt.Errorf("open %s: %w", e.Path, err)
		}

		// TeeReader: read from file, write to hasher + compressor simultaneously.
		tr := io.TeeReader(f, hasher)
		if _, err := io.Copy(pcomp, tr); err != nil {
			_ = f.Close()
			return fmt.Errorf("copy %s: %w", e.Path, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close %s: %w", e.Path, err)
		}
	}

	// Close compressor first (flushes zstd).
	if err := comp.Close(); err != nil {
		return fmt.Errorf("close compressor: %w", err)
	}

	// Close encryptor.
	if err := cw.Close(); err != nil {
		return fmt.Errorf("close encryptor: %w", err)
	}

	hash := hasher.Sum(nil)
	fmt.Printf("\nSHA-512: %x\n", hash)
	_ = hashOff

	// Close output file explicitly to catch write errors.
	if err := out.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	return nil
}
