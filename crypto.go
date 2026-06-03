package main

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Argon2id parameters
	argonMemory      = 64 * 1024 // 64 MB
	argonIterations  = 3
	argonParallelism = 2
	argonSaltLen     = 16
	argonKeyLen      = 32 // 256 bits for XChaCha20

	// XChaCha20-Poly1305 nonce size
	xchachaNonceLen = 24
)

// DeriveKey generates encryption key from password and salt using Argon2id
func DeriveKey(password, salt []byte) ([]byte, error) {
	if len(salt) != argonSaltLen {
		return nil, fmt.Errorf("salt must be %d bytes", argonSaltLen)
	}

	key := argon2.IDKey(password, salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)
	return key, nil
}

// Encrypt encrypts plaintext with XChaCha20-Poly1305
func Encrypt(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce := make([]byte, xchachaNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal appends encrypted data to nonce
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext with XChaCha20-Poly1305
// Returns error if authentication fails
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(ciphertext) < xchachaNonceLen {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:xchachaNonceLen]
	encrypted := ciphertext[xchachaNonceLen:]

	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: wrong password or corrupted data")
	}

	return plaintext, nil
}
