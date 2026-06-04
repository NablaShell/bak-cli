# bak-cli — Zero-Branding Secure Archive Utility

[![Go Version](https://img.shields.io/badge/Go-1.26.3-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Security: gosec passing](https://img.shields.io/badge/Security-gosec%20passing-success.svg)](docs/SecurityAudit_RemediationReport.md)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)]()

A paranoid-grade CLI tool for packing any directory into a single encrypted binary blob with **zero metadata leakage**, followed by forensic-grade secure deletion of the original files.

> **Think:** You have an Obsidian vault, a `~/secrets` folder, or a project you want to **seal** into indistinguishable random bytes. No tar headers. No ZIP magic numbers. No JSON structure. Just noise. This tool makes that noise reversible — but only with your password.

---

## Why bak-cli?

| Feature | bak-cli | tar + gpg | 7z | VeraCrypt |
|---------|---------|-----------|----|-----------|
| **Zero-Branding** | ✅ No magic bytes | ❌ Tar headers visible | ❌ "7z" signature | ❌ VC volume header |
| **Streaming AEAD** | ✅ Chunked XChaCha20-Poly1305 | ⚠️ GPG config-dependent | ✅ AES-256 | ✅ |
| **Compression** | ✅ zstd (level 3) | ⚠️ gzip (slow) | ✅ LZMA2 | ❌ |
| **Anti-Forensics RAM** | ✅ mlock + burn | ❌ | ❌ | ❌ |
| **Duress Mode** | ✅ Emergency wipe | ❌ | ❌ | ⚠️ Hidden volume |
| **Safe Delete Originals** | ✅ 3-pass wipe | ❌ | ❌ | ❌ |
| **Single Binary Output** | ✅ One file | ✅ One file | ✅ | ❌ Container |
| **OOM-Proof** | ✅ Bounded memory | ❌ | ❌ | ❌ |
| **Progress Bar** | ✅ Real-time | ❌ | ❌ | ❌ |
| **KDF** | Argon2id (64MB) | ⚠️ Varies | ⚠️ PBKDF2 | PBKDF2 |
| **Pure Go** | ✅ No cgo | System tools | C++ | Kernel module |

**Key differentiator:** If someone finds your `vault.bak`, it looks like `/dev/urandom` output. There are no headers, no magic numbers, no structure visible without the password. Even the file size reveals nothing — random data and zero-filled files compress to the same indistinguishable size.

---

## Benchmarks

Tested on Linux with 16GB RAM, encrypting a 17GB directory (3 × 5.5GB zero-filled blocks + 1 text file):

| Operation | Result |
|-----------|--------|
| **Vault size** | 1.8 MB (compression ratio ~10,000:1) |
| **Lock time** | ~2 minutes at 140 MB/s |
| **Unlock time** | 41 seconds |
| **Peak memory (lock)** | ~100 MB |
| **Peak memory (unlock)** | ~100 MB |
| **OOM?** | No |

Text-heavy directories (1000 Markdown files, 574KB):
| Operation | Result |
|-----------|--------|
| **Vault size** | 2.4 KB (compression ratio ~239:1) |

---

## How It Works

### Encryption Pipeline

```
User Password
     │
     ▼
┌─────────────┐      ┌──────────────────┐
│ Argon2id    │────▶ │ XChaCha20-       │
│ Memory: 64MB│      │ Poly1305 Key     │
│ Time: 3     │      │ (256-bit)        │
│ Threads: 2  │      └────────┬─────────┘
└─────────────┘               │
                              ▼
┌──────────────────┐  ┌──────────────┐
│ Salt (16 bytes)  │  │ Plaintext    │
│ Random           │  │ Payload      │
└──────────────────┘  └──────┬───────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ zstd Compress   │
                    │ (level 3)       │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Chunked         │
                    │ XChaCha20-      │
                    │ Poly1305        │
                    │ (24-byte nonce  │
                    │  per chunk)     │
                    └────────┬────────┘
                             │
                             ▼
              ┌──────────────────────────┐
              │ vault.bak (random bytes) │
              │ [Salt][Chunk1][Chunk2]...│
              └──────────────────────────┘
```

### Chunked Encryption Format

Instead of encrypting the entire payload as one blob (which requires loading everything into RAM), `bak-cli` splits data into chunks. Each chunk is independently encrypted with its own nonce:

```
vault.bak structure:
┌────────────────────────────────────────────┐
│ Salt (16 bytes)                            │
├────────────────────────────────────────────┤
│ Chunk 1:                                   │
│  ├─ Plaintext Length (4 bytes, big-endian) │
│  ├─ Nonce (24 bytes, random)               │
│  └─ Ciphertext + Poly1305 tag              │
├────────────────────────────────────────────┤
│ Chunk 2:                                   │
│  └─ ...                                    │
└────────────────────────────────────────────┘
```

**Why this matters:**
- Memory usage is bounded to `chunkSize` (auto-detected, typically 25% of available RAM, 256MB–1GB)
- A 17GB directory encrypts without exceeding ~100MB RAM
- Decryption reads one chunk at a time, writing files directly to disk
- Each chunk has an independent Poly1305 authentication tag — tampering is detected immediately

### Internal Payload Structure (Inside Compressed + Encrypted Block)

```
┌────────────────────────────────────────────────┐
│ Format Version   │ 2 bytes  │ big-endian       │
├────────────────────────────────────────────────┤
│ DirName Length   │ 4 bytes  │ big-endian       │
├────────────────────────────────────────────────┤
│ DirName          │ N bytes  │ UTF-8            │
├────────────────────────────────────────────────┤
│ SHA-512 Hash     │ 64 bytes │ Integrity check  │
├────────────────────────────────────────────────┤
│ Magic Separator  │ 4 bytes  │ 0x0BADC0DE       │
├────────────────────────────────────────────────┤
│ File Entry 1                                   │
│  ├─ PathLen     │ 4 bytes                      │
│  ├─ Path        │ N bytes                      │
│  ├─ DataSize    │ 8 bytes                      │
│  └─ Data        │ N bytes                      │
├────────────────────────────────────────────────┤
│ File Entry 2...                                │
└────────────────────────────────────────────────┘
```

---

## Security Features

### 1. Zero-Branding
The vault file contains **no recognizable structure** without the key:
- No magic bytes (unlike ZIP's `PK`, 7z's `7z`, tar's `ustar`)
- No JSON/XML/metadata headers
- No length fields in plaintext
- Entropy distribution indistinguishable from random data

**Why this matters:** Automated censorship circumvention tools, border searches, and forensic software look for file signatures. Your vault triggers none of them.

### 2. Memory Protection (Anti-Forensics)

```
// Password & key are locked to RAM (no swap)
syscall.Mlock(sensitiveSlice)

// Explicit zeroing after use
func Burn(data []byte) {
    for i := range data {
        data[i] = 0
    }
    runtime.KeepAlive(data)
}
```

- **mlock()** prevents sensitive data from being paged to disk (swap)
- **Burn()** zeroes memory immediately after use, with compiler optimization guard
- All sensitive data uses `[]byte`, never `string` (Go strings are immutable and linger in memory)

### 3. Chunked AEAD with XChaCha20-Poly1305

- **24-byte nonce per chunk** — safe for encrypting petabytes without nonce reuse risk
- **Poly1305 authentication tag per chunk** — any tampering or wrong password is detected immediately on the first corrupted chunk
- **4-byte length prefix** — enables streaming decryption without knowing total size
- **Constant-time MAC verification** — no timing side-channels on auth check

### 4. Argon2id Key Derivation

```
Memory: 64 MB
Iterations: 3
Parallelism: 2
```

- Memory-hard function resistant to GPU/ASIC attacks
- 64MB makes parallel brute-force expensive (~1GB per 16 attempts on GPU)
- Argon2id variant protects against both side-channel and time-memory tradeoff attacks

### 5. Zstd Compression Before Encryption

- **Level 3** — fast, balanced compression (~500 MB/s)
- **Reduces vault size** — 17GB of zeros → 1.8MB vault
- **Increases entropy density** — compressed data looks more random, harder to analyze
- **Streaming** — compresses on-the-fly without buffering entire payload

### 6. Duress Mode

```
# Set a duress password:
./bak-cli --unlock vault.bak --duress "panic2024"
# Type the duress password when prompted
# Result: Vault is destroyed, original data stays safe (already wiped)
```

When the duress password is entered, the vault file is **immediately overwritten with random data and deleted** — no decryption, no recovery possible. Plausible deniability: "The file must have been corrupted."

### 7. Secure Deletion of Originals

After encryption, the original directory is wiped using a **3-pass overwrite**:
1. **Pass 1:** Random bytes
2. **Pass 2:** Random bytes (different)
3. **Pass 3:** Zeroes

Each pass calls `fsync()` to ensure data hits the physical medium. Then the directory tree is removed.

---

## Installation

### From Source

```
git clone https://github.com/NablaShell/bak-cli.git
cd bak-cli
go build -o bak-cli .
sudo mv bak-cli /usr/local/bin/
```

### Requirements
- Go 1.26+
- Linux/macOS (uses `syscall.Mlock`, `/proc/meminfo`)

### Dependencies
- `golang.org/x/crypto` — Argon2id + XChaCha20-Poly1305
- `golang.org/x/term` — Hidden password input
- `github.com/klauspost/compress` — zstd compression

---

## Usage

### Lock (Seal) a Directory

```
# Basic usage
./bak-cli --lock ~/my-obsidian-vault

# Custom output path
./bak-cli --lock ~/secrets --output /mnt/backup/sealed.bak

# Verbose mode (shows progress, hash, chunk size)
./bak-cli --lock ~/projects --verbose
```

**What happens:**
1. Recursively scans all files in the directory
2. Asks for password (hidden input) + confirmation
3. Auto-detects optimal chunk size based on available RAM
4. Derives key via Argon2id
5. Compresses with zstd
6. Encrypts in chunks with XChaCha20-Poly1305
7. Writes `vault.bak` (pure random bytes)
8. **Securely wipes** the original directory (3-pass overwrite + delete)

### Unlock (Reveal) a Vault

```
# Basic unlock
./bak-cli --unlock vault.bak

# With duress protection
./bak-cli --unlock vault.bak --duress "emergency-password"

# Verbose unlock
./bak-cli --unlock vault.bak --verbose
```

> There are plans to change the operating principle to a normal duress-pass that will work natively with a regular unlock. So for now //TODO

**What happens:**
1. Reads salt from the first 16 bytes
2. Asks for password
3. If password == duress password → **immediate secure wipe** of vault (with confirmation)
4. Derives key via Argon2id
5. Decrypts chunk by chunk (bounded memory)
6. Decompresses with zstd
7. Recreates directory structure with original folder name
8. Restores all files to disk (streaming, no full buffering)

### Options

```
--lock <dir>      Directory to seal
--unlock <file>   Vault file to open
--output, -o      Output vault path (default: vault.bak)
--duress <pass>   Emergency password that destroys the vault
--verbose, -v     Show progress bar and details
--help, -h        Show help
```

---

## Architecture

```
bak-cli/
├── main.go                 # Entry point, CLI orchestration
├── go.mod
├── internal/
│   ├── cli/
│   │   ├── args.go         # Flag parsing
│   │   └── input.go        # Password input, confirmation
│   ├── compress/
│   │   └── zstd.go         # zstd compression/decompression wrappers
│   ├── crypto/
│   │   ├── argon.go        # Argon2id key derivation
│   │   ├── chunks.go       # Chunked AEAD encryption/decryption
│   │   └── memguard.go     # mlock, burn, memory protection
│   ├── progress/
│   │   └── bar.go          # Real-time progress bar
│   ├── vault/
│   │   ├── format.go       # Binary format constants
│   │   ├── pack.go         # Directory packing (scan + compress + encrypt)
│   │   └── unpack.go       # Streaming unpack (decrypt + decompress + restore)
│   └── wipe/
│       └── wipe.go         # Secure 3-pass file/directory deletion
```

### Data Flow

```
[Files on Disk]
     │
     ▼
[ScanDirectory] ── sorted entries
     │
     ▼
[Build Metadata] ── version, dirname, hash placeholder, magic
     │
     ▼
[zstd Compress] ── streaming, level 3
     │
     ▼
[ChunkedWriter] ── split into N chunks, each with nonce + AEAD
     │
     ▼
[vault.bak] ── [Salt][Chunk1][Chunk2]...
```

```
[vault.bak]
     │
     ▼
[ChunkedReader] ── read chunk by chunk, verify Poly1305 per chunk
     │
     ▼
[zstd Decompress] ── streaming decompression
     │
     ▼
[Parse Header] ── version, dirname, magic
     │
     ▼
[Restore Files] ── create directories, write files as read (no full buffer)
     │
     ▼
[Restored Directory]
```

---

## Threat Model

### What bak-cli Protects Against

| Threat | Protection |
|--------|-----------|
| **Passive forensic analysis** | Zero-branding — file looks like random data |
| **Active forensic analysis** | Memory locked, zeroed after use |
| **Bruteforce attacks** | Argon2id (64MB), authenticated encryption per chunk |
| **Password coercion** | Duress mode — instant destruction |
| **Swap/file recovery** | mlock() prevents swap, 3-pass overwrite |
| **Data tampering** | Poly1305 per chunk + SHA-512 integrity |
| **Nonce reuse** | 24-byte unique nonce per chunk |
| **OOM attacks** | Chunked I/O, memory bounded to ~256MB–1GB |
| **Traffic analysis (size)** | zstd compression normalizes output size across data types |

### What bak-cli Does NOT Protect Against

- **Keyloggers** — Hardware or software keyloggers can capture your password
- **Cold boot attacks** — RAM can be read before it decays if attacker has physical access
- **Evil maid attacks** — Someone could replace the binary with a backdoored version
- **Compromised OS** — If your kernel is compromised, mlock() can be bypassed
- **Side-channel on the machine itself** — Power analysis, EM emanations

---

## Comparison with Alternatives

### vs tar + gpg

```
# Traditional approach
tar czf - ~/secrets | gpg --symmetric --cipher-algo AES256 > secrets.tar.gz.gpg
```

**Problems:**
- `gpg` leaves key material in swap
- Tar headers are visible before decryption (`ustar`, filenames, sizes)
- No memory protection
- No secure deletion of originals
- GPG configuration varies wildly (some use weak KDFs)
- File is identifiable as GPG data
- gzip is slow compared to zstd
- No progress indication
- Entire archive must fit in RAM

### vs 7-Zip

```
7z a -p -mhe=on secrets.7z ~/secrets
```

**Problems:**
- 7z format has recognizable headers even with `-mhe=on`
- No memory locking
- No duress mode
- Uses PBKDF2 with low iteration count by default
- C++ codebase (larger attack surface)
- No built-in secure deletion of originals
- LZMA2 is 10x slower than zstd for similar ratios

### vs VeraCrypt

**Problems:**
- Requires kernel module (not always available)
- Container files have VC headers
- Fixed container size (wastes space or risks overflow)
- Overkill for single-directory archiving
- No built-in secure deletion of originals
- No compression
- No duress mode (hidden volumes are complex and detectable)

### Why bak-cli Wins for Directory Archiving

- **Purpose-built** — Just seals directories, nothing else
- **Minimal attack surface** — ~800 lines of Go, auditable in an afternoon
- **Paranoid defaults** — Maximum security, no configuration needed
- **Zero trust** — Assumes the encrypted file will be inspected by adversaries
- **Plausible deniability** — Vault file looks like random noise, duress password destroys evidence
- **OOM-proof** — Chunked processing handles terabytes on machines with limited RAM
- **Fast** — zstd compression at 500 MB/s, chunked I/O maximizes throughput
- **Transparent** — Progress bar shows exactly what's happening

---

## Verified Test Results

### Test 1: Large directory with compression (17GB zeros)

```
$ du -sh test_big
17G     test_big

$ ./bak-cli --lock test_big --output big.bak --verbose
Password:
Confirm:
Chunk size: 1024 MB
Packing ██████████████████████████████████████████████░ 16.1 GB/16.1 GB 140.0 MB/s
SHA-512: 7cfcbed683a96a5...
Wiping source...
Done.

$ du -sh big.bak
1.8M    big.bak

$ ./bak-cli --unlock big.bak --verbose
Password:
Decrypting ███████████████████████████████████████████████ 100% 1.8 MB/1.8 MB
Restored: test_big
Done.

$ du -sh test_big
17G     test_big
```

**Result:** 17GB → 1.8MB vault. Lock in ~2 min, unlock in 41 sec. Peak RAM: ~100 MB.

### Test 2: Text-heavy directory (1000 Markdown files, 574KB)

```
$ du -sh test_text
574K    test_text

$ ./bak-cli --lock test_text --output text.bak --verbose
Done.

$ ls -lh text.bak
2.4K    text.bak
```

**Result:** 574KB → 2.4KB vault. Compression ratio: **239:1**.

### Test 3: Mixed random + text (10MB random + text)

```
$ du -sh test_mixed
11M     test_mixed

$ ls -lh mixed.bak
~10M    mixed.bak
```

**Result:** Random data doesn't compress (as expected), text portions compress well. Vault size ≈ original random data size.

---

## Disclaimer

This tool uses strong cryptography and anti-forensic techniques. **Test thoroughly before trusting it with real data.** Always verify that you can successfully restore your files before deleting the originals.

The secure deletion feature attempts to prevent file recovery, but **cannot guarantee 100% unrecoverability** on all filesystems (especially SSDs with wear leveling, journaling filesystems, or RAID arrays). For maximum security:
- Use full-disk encryption (LUKS, FileVault)
- Store vaults on encrypted volumes
- Never enter passwords on untrusted hardware
- Verify SHA-512 hashes after restoration

---

##  Contact & Connectivity

I prefer decentralized and encrypted communication channels.

*   **Session ID**: 05f08d7242fe9cd621e98ef902cd1a21a8bf10d0c7c946e8c8e469d2396657a637 
> Preferred for quick chats)
*   **Proton Mail**: `nabla.shell@proton.me` (For long-form inquiries; PGP preferred)
*   **PGP Key**: Available in [here](/docs/public_key.asc)
    *PGP Fingerprint: 885F 3675 1D87 3F99 55ED 0ABC D1F6 A559 1458 507D*

## Funding

If bak-cli helps your OpSec, consider supporting the project.
Cryptocurrency	Address

## Support the Project 

If you find **bak-cli** useful, consider supporting its development:

| Asset | Address |
| :--- | :--- |
| **BTC** | 8Arc4tRdGAKcWNMLCb7mj2fnYqWgQGhTTgR7FEGaZpL2Pw6MNSwqsGMUGpeQGURgQbDoyxU1ASKMP7dKBJq8yJgCSwCgPYe |
| **XMR** | bc1qktffxm3579v6zs6mpms4yvwp6m067nkggd8ach |

---

## License

GPL-3.0 license — see LICENSE for details.

---

## Star This Project

If you find this tool useful, consider starring it on GitHub. It helps others discover privacy-focused tools.

**Remember:** In a world of mass surveillance, encryption is not a crime — it's a responsibility.

---

**Made with paranoia and Go.**  
*"Trust no one. Encrypt everything."*
