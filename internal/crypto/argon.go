package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	SaltSize = 16
	KeySize  = 32

	argonMemory      = 64 * 1024
	argonIterations  = 3
	argonParallelism = 2
)

// GenerateSalt creates a random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a 256-bit key from password and salt.
func DeriveKey(password, salt []byte) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be %d bytes, got %d", SaltSize, len(salt))
	}
	return argon2.IDKey(password, salt, argonIterations, argonMemory, argonParallelism, KeySize), nil
}
