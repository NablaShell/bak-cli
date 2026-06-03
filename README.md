# bak-cli — Zero-Branding Secure Archive Utility

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)]()
[![Security](https://img.shields.io/badge/audit-please-red)]()

A paranoid-grade CLI tool for packing any directory into a single encrypted binary blob with **zero metadata leakage**, followed by forensic-grade secure deletion of the original files.

> **Think:** You have an Obsidian vault, a `~/secrets` folder, or a project you want to **seal** into indistinguishable random bytes. No tar headers. No ZIP magic numbers. No JSON structure. Just noise. This tool makes that noise reversible — but only with your password.

---

##  Why bak-cli?
```
| Feature | bak-cli | tar + gpg | 7z | VeraCrypt |
|---------|---------|-----------|----|-----------|
| **Zero-Branding** | ✅ No magic bytes | ❌ Tar headers visible | ❌ "7z" signature | ❌ VC volume header |
| **AEAD (Authenticated Encryption)** | ✅ XChaCha20-Poly1305 | ⚠️ GPG config-dependent | ✅ AES-256 | ✅ |
| **Anti-Forensics RAM** | ✅ mlock + burn | ❌ | ❌ | ❌ |
| **Duress Mode** | ✅ Emergency wipe | ❌ | ❌ | ⚠️ Hidden volume |
| **Safe Delete Originals** | ✅ 3-pass wipe | ❌ | ❌ | ❌ |
| **Single Binary Output** | ✅ One file | ✅ One file | ✅ | ❌ Container |
| **KDF** | Argon2id (64MB) | ⚠️ Varies | ⚠️ PBKDF2 | PBKDF2/RIPEMD |
| **No External Dependencies** | ✅ Pure Go | System tools | System tools | Kernel module |
```
**Key differentiator:** If someone finds your `vault.bak`, it looks like `/dev/urandom` output. There are no headers, no magic numbers, no structure visible without the password. Even the file size reveals nothing — it's indistinguishable from random data of the same length.

---

##  How It Works

### Encryption Pipeline
```
User Password
│
▼
┌─────────────┐ ┌──────────────────┐
│ Argon2id │────▶│ XChaCha20- │
│ Memory: 64MB │ │ Poly1305 Key │
│ Time: 3 │ │ (256-bit) │
│ Threads: 2 │ └────────┬─────────┘
└─────────────┘ │
▼
┌──────────────────┐ ┌──────────────┐
│ Salt (16 bytes) │ │ Plaintext │
│ Random │ │ Payload │
└──────────────────┘ └──────┬───────┘
│
▼
┌─────────────────┐
│ XChaCha20- │
│ Poly1305 Seal │
│ (24-byte nonce) │
└────────┬────────┘
│
▼
┌──────────────────────────┐
│ vault.bak (random bytes) │
│ [Salt][Nonce+Ciphertext] │
└──────────────────────────┘
```


### Internal Payload Structure (Inside Encrypted Block)
```
┌────────────────────────────────────────────────┐
│ DirName Length │ 4 bytes │ BigEndian uint32 │
├────────────────────────────────────────────────┤
│ DirName │ N bytes │ Original folder │
│ │ │ name (UTF-8) │
├────────────────────────────────────────────────┤
│ SHA-512 Hash │ 64 bytes │ Integrity check │
│ │ │ of file payload │
├────────────────────────────────────────────────┤
│ Magic Separator │ 4 bytes │ 0x0BADC0DE │
├────────────────────────────────────────────────┤
│ File Entry 1 │
│ ├─ PathLen │ 4 bytes │
│ ├─ Path │ N bytes │
│ ├─ DataSize │ 8 bytes │
│ └─ Data │ N bytes │
├────────────────────────────────────────────────┤
│ File Entry 2... │
└────────────────────────────────────────────────┘
```

The **magic separator** `0x0BADC0DE` helps detect structural corruption early, and the **SHA-512 hash** ensures not a single byte was tampered with — even before you notice missing files.

---

##  Security Features

### 1. Zero-Branding
The vault file contains **no recognizable structure** without the key:
- No magic bytes (unlike ZIP's `PK`, 7z's `7z`, tar's `ustar`)
- No JSON/XML/metadata headers
- No length fields in plaintext
- Entropy distribution indistinguishable from random data

**Why this matters:** Automated censorship circumvention tools, border searches, and forensic software look for file signatures. Your vault triggers none of them.

### 2. Memory Protection (Anti-Forensics)

```go
// Password & key are locked to RAM (no swap)
unix.Mlock(sensitiveSlice)

// Explicit zeroing after use
func Burn(data []byte) {
    for i := range data {
        data[i] = 0
    }
    runtime.KeepAlive(data) // Prevents compiler optimization
}
```
    mlock() prevents sensitive data from being paged to disk (swap)

    Burn() zeroes memory immediately after use, with compiler optimization guard

    All sensitive data uses []byte, never string (Go strings are immutable and linger in memory)

3. AEAD with XChaCha20-Poly1305

    24-byte nonce — safe for encrypting terabytes of data without nonce reuse risk

    Poly1305 authentication tag — any tampering or wrong password is detected immediately

    Constant-time MAC verification — no timing side-channels on auth check

4. Argon2id Key Derivation
```text

Memory: 64 MB
Iterations: 3
Parallelism: 2

    Memory-hard function resistant to GPU/ASIC attacks

    64MB makes parallel brute-force expensive (~1GB per 16 attempts on GPU)

    Argon2id variant protects against both side-channel and time-memory tradeoff attacks
```
5. Duress Mode
```bash

# Set a panic password when creating:
./bak-cli --lock ~/secrets --output vault.bak

# If forced to decrypt, use the duress password:
./bak-cli --unlock vault.bak --duress "panic1234"
# Output:  Duress password detected! Securely deleting vault...
# Vault successfully destroyed.
```
When the duress password is entered, the vault file is immediately overwritten with random data and deleted — no decryption, no recovery possible. Plausible deniability: "The file must have been corrupted."
6. Secure Deletion of Originals

After encryption, the original directory is wiped using a 3-pass overwrite:

    Pass 1: Random bytes

    Pass 2: Random bytes (different)

    Pass 3: Zeroes

Each pass calls fsync() to ensure data hits the physical medium. Then os.RemoveAll() is called. This makes recovery via filesystem journaling or magnetic remnant analysis significantly harder.
 Installation
From Source (Recommended)
```bash

git clone https://github.com/NablaShell/bak-cli.git
cd bak-cli
go build -o bak-cli
sudo mv bak-cli /usr/local/bin/
```
Requirements

    Go 1.26+ (uses new -Xnodwarf5 features)

    Linux/macOS (uses unix.Mlock, syscall.Stdin)

Dependencies

    golang.org/x/crypto — Argon2id + XChaCha20-Poly1305

    golang.org/x/term — Hidden password input

 Usage
Lock (Seal) a Directory
```bash

# Basic usage
./bak-cli --lock ~/my-obsidian-vault

# Custom output path
./bak-cli --lock ~/secrets --output /mnt/backup/sealed.bak

# Verbose mode (shows hash, file count)
./bak-cli --lock ~/projects --verbose
```
What happens:

    Recursively reads all files in the directory

    Stores the directory name in metadata

    Computes SHA-512 integrity hash

    Asks for password (hidden input) + confirmation

    Derives key via Argon2id

    Encrypts everything with XChaCha20-Poly1305

    Writes vault.bak (pure random bytes)

    Securely wipes the original directory (3-pass overwrite + delete)

Unlock (Reveal) a Vault
```bash

# Basic unlock
./bak-cli --unlock vault.bak

# With duress protection
./bak-cli --unlock vault.bak --duress "emergency-password"

# Verbose unlock
./bak-cli --unlock vault.bak --verbose
```
What happens:

    Reads salt from the first 16 bytes

    Asks for password

    If password == duress password → immediate secure wipe of vault

    Derives key via Argon2id

    Attempts decryption + Poly1305 authentication

    If auth fails → exit(1) with no further info (anti-bruteforce)

    Verifies SHA-512 integrity of payload

    Recreates directory structure with original folder name

    Restores all files with original permissions

Emergency Duress
```bash

# Scenario: You're forced to decrypt your vault
# Pre-configure a duress password:
./bak-cli --unlock vault.bak --duress "i-swear-this-is-the-real-password"
# Type the duress password when prompted
# Result: Vault is destroyed, original data stays safe (it was already wiped during lock)
```
 Verification & Testing
Check Vault Integrity (Without Decrypting)
```bash

# Structural check (salt presence, minimum size)
./bak-cli --inspect vault.bak
```
Output:
```text

=== Vault File Info ===
filename                : vault.bak
size                    : 42.7 MB
permissions             : -rw-------
status                  : valid structure
salt                    : a1b2c3d4e5f6a7b8...
encrypted_data_size     : 42700000
encrypted_checksum      : f3a21c9b...
```
Verify Restoration
```bash

# Lock with verbose
./bak-cli --lock ~/test-data --verbose
# Output: SHA-512: d4e5f6a7b8c9...

# Unlock with verbose
./bak-cli --unlock vault.bak --verbose
# Output: Integrity hash: d4e5f6a7b8c9...
# Hashes match → data intact
```
🏗️Architecture
```text

bak-cli/
├── main.go          # CLI interface, flag parsing, password input
├── crypto.go        # Argon2id KDF, XChaCha20-Poly1305 encrypt/decrypt
├── vault.go         # Directory packing/unpacking, binary serialization
├── wipe.go          # Secure file/directory deletion (multi-pass overwrite)
└── memguard.go      # mlock() memory locking, burn() secure zeroing
```
Data Flow
```text

[Files on Disk] ──▶ [PackDirectory()] ──▶ [Serialize()] ──▶ [SHA-512 Hash]
                                                                    │
                                                                    ▼
[User Input] ──▶ [Argon2id] ──▶ [Encrypt()] ──▶ [vault.bak]
     │                                                   
     └── [mlock()] password & key in RAM
                                                          
[vault.bak] ──▶ [Decrypt()] ──▶ [Verify SHA-512] ──▶ [Deserialize()]
                                                              │
                                                              ▼
                                                    [UnpackDirectory()]
                                                              │
                                                              ▼
                                                     [Restored Files]
```
 Threat Model
What bak-cli Protects Against
Threat	Protection
Passive forensic analysis	Zero-branding — file looks like random data
Active forensic analysis	Memory locked, zeroed after use
Bruteforce attacks	Argon2id (64MB), authenticated encryption
Password coercion	Duress mode — instant destruction
Swap/file recovery	mlock() prevents swap, 3-pass overwrite
Data tampering	Poly1305 MAC + SHA-512 integrity
Nonce reuse	24-byte XChaCha nonce, generated per encryption
What bak-cli Does NOT Protect Against

    Keyloggers — Hardware or software keyloggers can capture your password

    Cold boot attacks — RAM can be read before it decays if attacker has physical access within minutes

    Evil maid attacks — Someone could replace the binary with a backdoored version

    Traffic analysis — The file size may correlate with the original directory size

    Compromised OS — If your kernel is compromised, mlock() can be bypassed

 Comparison with Alternatives
vs tar + gpg
```bash

# Traditional approach
tar czf - ~/secrets | gpg --symmetric --cipher-algo AES256 > secrets.tar.gz.gpg
```
Problems:

    gpg leaves key material in swap

    Tar headers are visible before decryption (ustar, filenames, sizes)

    No memory protection

    No secure deletion of originals

    GPG configuration varies wildly (some use weak KDFs)

    File is identifiable as GPG data

vs 7-Zip
```bash

7z a -p -mhe=on secrets.7z ~/secrets
```
Problems:

    7z format has recognizable headers even with -mhe=on

    No memory locking

    No duress mode

    Uses PBKDF2 with low iteration count by default

    C++ codebase (larger attack surface)

vs VeraCrypt

Problems:

    Requires kernel module (not always available)

    Container files have VC headers

    Fixed container size (wastes space or risks overflow)

    Overkill for single-directory archiving

    No built-in secure deletion of originals

Why bak-cli Wins for Directory Archiving

    Purpose-built — Just seals directories, nothing else

    Minimal attack surface — ~500 lines of Go, auditable in an afternoon

    Paranoid defaults — Maximum security, no configuration needed

    Zero trust — Assumes the encrypted file will be inspected by adversaries

    Plausible deniability — Vault file looks like random noise, duress password destroys evidence

  Development
Building
```bash

go build -o bak-cli
```
Running Tests
```bash

# Unit tests
go test ./...

# Integration test (creates and restores a test directory)
./test/integration.sh
```
Memory Leak Check
```bash

# Check if passwords persist in memory after Burn()
go build -gcflags="-m"  # Check for escape analysis
# Use pprof or Valgrind for deeper analysis
```
Contributing

    Fork the repository

    Create a feature branch

    Ensure all tests pass

    Submit a PR with detailed description

Areas for contribution:

    Windows support (different mlock API)

    Compression layer (zstd before encryption)

    Shamir's Secret Sharing (split key across multiple files)

    Hardware security key support (YubiKey, etc.)

 Disclaimer

This tool uses strong cryptography and anti-forensic techniques. Test thoroughly before trusting it with real data. Always verify that you can successfully restore your files before deleting the originals.

The secure deletion feature (WipeDirectory) attempts to prevent file recovery, but cannot guarantee 100% unrecoverability on all filesystems (especially SSDs with wear leveling, journaling filesystems, or RAID arrays). For maximum security:

    Use full-disk encryption (LUKS, FileVault)

    Store vaults on encrypted volumes

    Never enter passwords on untrusted hardware

    Verify SHA-512 hashes after restoration

 License

GPL-3.0 license  — see LICENSE for details.

 Star This Project

If you find this tool useful, consider starring it on GitHub. It helps others discover privacy-focused tools.

Remember: In a world of mass surveillance, encryption is not a crime — it's a responsibility.

Made with paranoia and Go.
"Trust no one. Encrypt everything."
