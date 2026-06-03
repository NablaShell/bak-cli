# bak-cli — Zero-Branding Secure Archive Utility

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)]()
[![Security](https://img.shields.io/badge/audit-please-red)]()

A paranoid-grade CLI tool for packing any directory into a single encrypted binary blob with **zero metadata leakage**, followed by forensic-grade secure deletion of the original files.

> **Think:** You have an Obsidian vault, a `~/secrets` folder, or a project you want to **seal** into indistinguishable random bytes. No tar headers. No ZIP magic numbers. No JSON structure. Just noise. This tool makes that noise reversible — but only with your password.

---

##  Why bak-cli?

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

**Key differentiator:** If someone finds your `vault.bak`, it looks like `/dev/urandom` output. There are no headers, no magic numbers, no structure visible without the password. Even the file size reveals nothing — it's indistinguishable from random data of the same length.

---

##  How It Works

### Encryption Pipeline
```
       ┌─────────────────┐
       |  User Password  |
       └────────┬────────┘
                │
                ▼
      ┌─────────────────┐
      │    Argon2id     │
      │  Memory: 64MB   │
      │    Time: 3      │
      │   Threads: 2    │
      └────────┬────────┘
               │
               │ (Derive Key)
               ▼
┌──────────────────────────────┐
│  XChaCha20-Poly1305 Key      │
│          (256-bit)           │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐       ┌──────────────────────────────┐
│       Salt (16 bytes)        │       │      Plaintext Payload       │
│        Secure Random         │       │        (Packed Data)         │
└──────────────┬───────────────┘       └──────────────┬───────────────┘
               │                                      │
               └───────────────────┬──────────────────┘
                                   │
                                   ▼
                       ┌───────────────────────┐
                       │ XChaCha20-Poly1305    │
                       │ AEAD Seal Operation   │
                       │ (24-byte random nonce)│
                       └───────────┬───────────
                                   │
                                   ▼
                      ┌──────────────────────────┐
                      │ vault.bak (random bytes) │
                      │ [Salt][Nonce+Ciphertext] │
                      └──────────────────────────┘
```


### Internal Payload Structure (Inside Encrypted Block)
```
┌──────────────────┬───────────┬────────────────────────────────────────┐
│      FIELD       │   SIZE    │              DESCRIPTION               │
├──────────────────┼───────────┼────────────────────────────────────────┤
│ DirName Length   │  4 bytes  │ BigEndian uint32                       │
├──────────────────┼───────────┼────────────────────────────────────────┤
│ DirName          │  N bytes  │ Original folder name (UTF-8)           │
├──────────────────┼───────────┼────────────────────────────────────────┤
│ SHA-512 Hash     │ 64 bytes  │ Integrity check of file payload        │
├──────────────────┼───────────┼────────────────────────────────────────┤
│ Magic Separator  │  4 bytes  │ 0x0BADC0DE                             │
├──────────────────┴───────────┴────────────────────────────────────────┤
│ File Entry 1                                                          │
│  ├─ PathLen      │  4 bytes  │ BigEndian uint32                       │
│  ├─ Path         │  N bytes  │ Relative file path (UTF-8)             │
│  ├─ DataSize     │  8 bytes  │ BigEndian uint64                       │
│  └─ Data         │  N bytes  │ Raw file content                       │
├───────────────────────────────────────────────────────────────────────┤
│ File Entry 2... (Repeats until EOF)                                   │
└───────────────────────────────────────────────────────────────────────┘
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
- mlock() prevents sensitive data from being paged to disk (swap)

- Burn() zeroes memory immediately after use, with compiler optimization guard

- All sensitive data uses []byte, never string (Go strings are immutable and linger in memory)

### 3. AEAD with XChaCha20-Poly1305

- 24-byte nonce — safe for encrypting terabytes of data without nonce reuse risk

- Poly1305 authentication tag — any tampering or wrong password is detected immediately

- Constant-time MAC verification — no timing side-channels on auth check

### 4. Argon2id Key Derivation

Memory: 64 MB
Iterations: 3
Parallelism: 2

- Memory-hard function resistant to GPU/ASIC attacks

- 64MB makes parallel brute-force expensive (~1GB per 16 attempts on GPU)

- Argon2id variant protects against both side-channel and time-memory tradeoff attacks

### 5. Duress Mode
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

- Pass 1: Random bytes

- Pass 2: Random bytes (different)

- Pass 3: Zeroes

Each pass calls fsync() to ensure data hits the physical medium. Then os.RemoveAll() is called. This makes recovery via filesystem journaling or magnetic remnant analysis significantly harder.
## Installation
### From Source (Recommended)
```bash
git clone https://github.com/NablaShell/bak-cli.git
cd bak-cli
go build -o bak-cli
sudo mv bak-cli /usr/local/bin/
```
### Requirements

    Go 1.26+ (uses new -Xnodwarf5 features)

    Linux/macOS (uses unix.Mlock, syscall.Stdin)

### Dependencies

    golang.org/x/crypto — Argon2id + XChaCha20-Poly1305

    golang.org/x/term — Hidden password input

## Usage
### Lock (Seal) a Directory
```bash
# Basic usage
./bak-cli --lock ~/my-obsidian-vault

# Custom output path
./bak-cli --lock ~/secrets --output /mnt/backup/sealed.bak

# Verbose mode (shows hash, file count)
./bak-cli --lock ~/projects --verbose
```
What happens:

- Recursively reads all files in the directory

- Stores the directory name in metadata

- Computes SHA-512 integrity hash

- Asks for password (hidden input) + confirmation

- Derives key via Argon2id

- Encrypts everything with XChaCha20-Poly1305

- Writes vault.bak (pure random bytes)

- Securely wipes the original directory (3-pass overwrite + delete)

### Unlock (Reveal) a Vault
```bash
# Basic unlock
./bak-cli --unlock vault.bak

# With duress protection
./bak-cli --unlock vault.bak --duress "emergency-password"

# Verbose unlock
./bak-cli --unlock vault.bak --verbose
```
What happens:

- Reads salt from the first 16 bytes

- Asks for password

- If password == duress password → immediate secure wipe of vault

- Derives key via Argon2id

- Attempts decryption + Poly1305 authentication

- If auth fails → exit(1) with no further info (anti-bruteforce)

- Verifies SHA-512 integrity of payload

- Recreates directory structure with original folder name

- Restores all files with original permissions

### Emergency Duress
```bash
# Scenario: You're forced to decrypt your vault
# Pre-configure a duress password:
./bak-cli --unlock vault.bak --duress "i-swear-this-is-the-real-password"
# Type the duress password when prompted
# Result: Vault is destroyed, original data stays safe (it was already wiped during lock)
```
## Verification & Testing
### Check Vault Integrity (Without Decrypting)
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
### Verify Restoration
```bash
# Lock with verbose
./bak-cli --lock ~/test-data --verbose
# Output: SHA-512: d4e5f6a7b8c9...

# Unlock with verbose
./bak-cli --unlock vault.bak --verbose
# Output: Integrity hash: d4e5f6a7b8c9...
# Hashes match → data intact
```
## Architecture
```text
bak-cli/
├── main.go          # CLI interface, flag parsing, password input
├── crypto.go        # Argon2id KDF, XChaCha20-Poly1305 encrypt/decrypt
├── vault.go         # Directory packing/unpacking, binary serialization
├── wipe.go          # Secure file/directory deletion (multi-pass overwrite)
└── memguard.go      # mlock() memory locking, burn() secure zeroing
```
## Data Flow
```
=== LOCK PIPELINE (Sealing) ===

[Files on Disk] ──▶ [PackDirectory()] ──▶ [Serialize()] ──▶ [SHA-512 Hash]
                                                                  │
                                                                  ▼
[User Input]    ──▶ [Argon2id]         ──▶ [Encrypt()]   ──▶ [vault.bak]
     │
     └──▶ [mlock()] Password & Key locked in RAM


=== UNLOCK PIPELINE (Restoring) ===

[vault.bak]     ──▶ [Decrypt()]        ──▶ [Verify SHA-512] ──▶ [Deserialize()]
                                                                      │
                                                                      ▼
                                                            [UnpackDirectory()]
                                                                      │
                                                                      ▼
                                                             [Restored Files]
```
## Threat Model

### What bak-cli Protects Against

| Threat | Protection Mechanism |
| :--- | :--- |
| **Passive forensic analysis** | **Zero-branding:** The output file contains no magic bytes or headers and is indistinguishable from pure random noise (high entropy). |
| **Active forensic analysis** | **Anti-forensics RAM protection:** Sensitive data is locked in memory and explicitly zeroed out immediately after use. |
| **Brute-force attacks** | **Argon2id KDF:** Configured with memory-hard parameters (64MB) to significantly increase the cost of GPU/ASIC cluster attacks. |
| **Password coercion** | **Duress mode:** Entering a pre-configured panic password triggers an immediate, unrecoverable secure wipe of the vault. |
| **Swap / File recovery** | **System-level mitigations:** `mlock()` prevents keys from leaking to swap space, and original files are overwritten using a 3-pass shredding process. |
| **Data tampering** | **Authenticated Encryption (AEAD):** Poly1305 MAC coupled with an internal SHA-512 payload hash ensures any unauthorized modifications are detected before decryption. |
| **Nonce reuse** | **Extended Nonce:** XChaCha20 uses a 24-byte random nonce, practically eliminating the risk of collision even across millions of vaults. |

### What bak-cli Does NOT Protect Against

While `bak-cli` is designed with paranoia in mind, it operates under standard cryptographic assumptions. It cannot protect you against the following vectors:

* **Keyloggers:** Hardware or software-based keyloggers running on your system can log your master password during entry.
* **Cold Boot Attacks:** If an attacker gains physical access to your machine while it's running (or within minutes of a shutdown), RAM modules can be frozen and read to extract cryptographic keys before they decay.
* **Evil Maid Attacks:** An adversary with physical access to your device could replace the compiled `bak-cli` binary in `/usr/bin/` with a backdoored version that leaks passwords or keys.
* **Traffic / Size Analysis:** The encrypted vault size correlates closely with the original directory size. If an adversary knows you have a folder that is exactly 42.7 MB, they might infer that a 42.7 MB vault corresponds to that folder.
* **Compromised OS / Kernel:** If your operating system kernel is compromised or running rootkits, system calls like `mlock()` can be bypassed, hooks can be placed on memory, and the process can be fully inspected.

## Comparison with Alternatives

### vs `tar` + `gpg`
```bash
# Traditional approach
tar czf - ~/secrets | gpg --symmetric --cipher-algo AES256 > secrets.tar.gz.gpg
```

**Flaws & Vulnerabilities:**
* **Information Leakage:** `tar` headers (metadata, original filenames, structures, and permissions) are often partially exposed or structured in a way that assists cryptanalysis before decryption.
* **No RAM Protection:** `gpg` does not strictly prevent key material or decrypted blocks from leaking into the system's swap space.
* **No Memory Hardening:** Standard GPG setups often rely on configurations that vary wildly, sometimes falling back to weaker or outdated Key Derivation Functions (KDFs).
* **Forensic Footprint:** The output file contains clear magic bytes identifying it explicitly as GPG-encrypted data.
* **No Safe Erasure:** It completely lacks built-in mechanism for forensic-grade deletion of the original directory.

---

### vs `7-Zip`
```bash
# Encrypting with header encryption enabled
7z a -p -mhe=on secrets.7z ~/secrets
```

**Flaws & Vulnerabilities:**
* **Signature Leakage:** Even with `-mhe=on` (header encryption), the `7z` format still writes recognizable signatures at the start of the file, making it a target for automated forensic filters.
* **Weak KDF Standards:** By default, 7-Zip utilizes PBKDF2 with relatively low iteration counts, rendering it significantly more vulnerable to modern GPU/ASIC brute-force clusters compared to Argon2id.
* **No Memory Defense:** Lacks `mlock()` or anti-forensic RAM wiping primitives (`burn`).
* **Attack Surface:** Built on a massive, legacy C++ codebase, which presents a substantially larger attack surface (buffer overflows, memory corruption) than a minimal Go binary.
* **No Duress Primitives:** Does not support emergency panic/coercion passwords.

---

### vs `VeraCrypt`

**Flaws & Vulnerabilities:**
* **Infrastructure Overhead:** Requires specific kernel modules or administrative privileges, making it a heavy dependency that isn't always available on minimal or live environments.
* **Volume Footprint:** Standard VeraCrypt volumes contain specific headers. While hidden volumes exist, managing them safely introduces high user-error risks.
* **Rigid Architecture:** Containers use fixed sizes. You either waste massive amounts of disk space pre-allocating a huge volume, or you risk running out of space as your folder grows.
* **No Native Shredding:** It does not handle the automated, multi-pass secure erasure of your source folders after a volume is created.

---

## Why bak-cli Wins for Directory Archiving

* **Purpose-Built:** It doesn't try to be a general-purpose archiver or a multi-platform virtual disk. It does exactly one thing: seals directories securely.
* **Minimal Attack Surface:** Comprising roughly ~500 lines of clean, readable, and modern Go code. It can be fully audited in less than an afternoon.
* **Paranoid Defaults:** Zero complex configuration files or risky CLI flags. The maximum security layer (Argon2id + XChaCha20-Poly1305 + Memguard) is hardcoded and fully non-negotiable.
* **Zero Trust Architecture:** It operates under the strict assumption that the output file will be captured, analyzed, and processed by powerful adversaries using professional forensic suites.
* **Plausible Deniability:** The final vault file looks precisely like random noise gathered from `/dev/urandom`. Furthermore, entering the pre-configured duress password completely destroys the evidence on the spot with a secure overwrite. 

## Development
### Building
```bash
go build -o bak-cli
```
### Running Tests
```bash

# Unit tests
go test ./...

# Integration test (creates and restores a test directory)
./test/integration.sh
```
### Memory Leak Check
```bash

# Check if passwords persist in memory after Burn()
go build -gcflags="-m"  # Check for escape analysis
# Use pprof or Valgrind for deeper analysis
```
##  Contributing

We welcome contributions from the community! Since `bak-cli` is licensed under the **GPL-3.0 License**, any forks, modifications, or derivative works must also remain open-source and free under the same terms.

### How to Contribute

1. **Fork the Repository:** Create your own copy of the project on GitHub.
2. **Create a Feature Branch:** Group your changes into a dedicated branch:
   ```bash
   git checkout -b feature/amazing-secure-feature
   ```
3. **Ensure All Tests Pass:** Run unit and integration tests before committing:
   ```bash
   go test ./...
   ```
4. **Submit a Pull Request (PR):** Open a PR against the `main` branch with a detailed description of your changes, architecture adjustments, and security implications.

---

### Roadmap & Areas for Contribution

If you want to help make `bak-cli` even more robust and versatile, consider picking up one of these highly anticipated features:

* **Windows Support:** Porting the core memory-locking features (`mlock`) and password-hiding terminals to Windows-specific APIs (using `VirtualLock` and Windows system calls).
* **Compression Layer:** Integrating a high-performance, stream-based compression layer (like `zstd` or `lz4`) to shrink the data payload *before* it passes through the encryption pipeline.
* **Shamir's Secret Sharing:** Adding an option to split the derived master key into multiple shards ($N$ of $M$ parts). The vault would require a specific threshold of key files to be present simultaneously to unlock.
* **Hardware Security Keys:** Implementing support for physical tokens (like YubiKey via HMAC-SHA1 challenge-response or FIDO2/U2F) to bind encryption keys to hardware, protecting against pure software-based master password compromise.
 
## Disclaimer

This tool uses strong cryptography and advanced anti-forensic techniques. **Test thoroughly with non-critical data before trusting it with your primary backups.** Always verify that you can successfully restore your files before allowing the tool to execute the automated deletion process.

The secure deletion feature (`WipeDirectory`) attempts to physically overwrite data to prevent file recovery. However, **it cannot guarantee 100% unrecoverability on all modern hardware and storage configurations**, specifically:
* **SSDs / NVMe drives:** Internal flash controllers utilize Wear Leveling, Over-Provisioning, and Translation Layers (FTL) that abstract physical sectors, meaning rewritten files may leave stale data in hidden blocks.
* **Journaling Filesystems:** Filesystems like `ext4`, `XFS`, or `APFS` may write metadata or file fragments to a journal log before committing them to the primary sectors.
* **RAID Arrays & Network Shares:** Multi-disk mirroring and remote protocols distribute data in ways that bypass local sector-overwrite operations.

**For maximum security and operational peace of mind:**
1. Combine this tool with Full-Disk Encryption (e.g., **LUKS** on Linux, **FileVault** on macOS).
2. Store your `.bak` vaults only on trusted, pre-encrypted file containers or physical volumes.
3. Never enter your master passwords on untrusted hardware, compromised hosts, or live-monitored environments.
4. Always utilize the `--verbose` flag to double-check that SHA-512 hashes match perfectly after restoration.

---

## License

This project is licensed under the **GPL-3.0 License** — see the [LICENSE](LICENSE) file for the full text and open-source compliance requirements.

---

## Star This Project

If you find this tool useful or if it fits your local security workflow, **consider starring it on GitHub!** It increases visibility and helps other privacy-focused developers discover alternative, zero-branding encryption utilities.

---

>  **Remember:** In a world of ubiquitous mass surveillance, encryption is not a crime — it is a fundamental responsibility.
> 
> *Made with high-grade paranoia and pure Go.*
> 
> **"Trust no one. Encrypt everything."**
