package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

const chunkLenSize = 4

// ChunkedWriter encrypts plaintext in chunks with length prefix and unique nonces.
type ChunkedWriter struct {
	w         io.Writer
	aead      cipher.AEAD
	chunkSize int
	buf       []byte
	total     int64
}

// NewChunkedWriter creates an encrypting writer.
func NewChunkedWriter(w io.Writer, key []byte, chunkSize int) (*ChunkedWriter, error) {
	if chunkSize < 16*1024*1024 {
		chunkSize = 16 * 1024 * 1024
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305: %w", err)
	}

	return &ChunkedWriter{
		w:         w,
		aead:      aead,
		chunkSize: chunkSize,
		buf:       make([]byte, 0, chunkSize),
	}, nil
}

func (cw *ChunkedWriter) Write(p []byte) (int, error) {
	cw.buf = append(cw.buf, p...)

	for len(cw.buf) >= cw.chunkSize {
		if err := cw.flush(); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

func (cw *ChunkedWriter) flush() error {
	if len(cw.buf) == 0 {
		return nil
	}

	n := cw.chunkSize
	if len(cw.buf) < n {
		n = len(cw.buf)
	}
	plain := cw.buf[:n]
	cw.buf = cw.buf[n:]

	// Safeguard against integer overflow.
	if len(plain) > math.MaxUint32 {
		return fmt.Errorf("chunk plaintext length %d exceeds uint32 limit", len(plain))
	}

	var lenBuf [chunkLenSize]byte
	// #nosec G115 - Length verified bounds checking
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(plain)))
	if _, err := cw.w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write chunk len: %w", err)
	}

	nonce := make([]byte, cw.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	if _, err := cw.w.Write(nonce); err != nil {
		return fmt.Errorf("write nonce: %w", err)
	}

	ciphertext := cw.aead.Seal(nil, nonce, plain, nil)
	if _, err := cw.w.Write(ciphertext); err != nil {
		return fmt.Errorf("write ciphertext: %w", err)
	}

	cw.total += int64(len(plain))
	return nil
}

func (cw *ChunkedWriter) Close() error {
	for len(cw.buf) > 0 {
		if err := cw.flush(); err != nil {
			return err
		}
	}
	return nil
}

func (cw *ChunkedWriter) TotalWritten() int64 { return cw.total }

// ChunkedReader reads and decrypts chunked data.
type ChunkedReader struct {
	r    io.Reader
	aead cipher.AEAD
	buf  []byte
	off  int
}

func NewChunkedReader(r io.Reader, key []byte) (*ChunkedReader, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305: %w", err)
	}
	return &ChunkedReader{r: r, aead: aead}, nil
}

func (cr *ChunkedReader) Read(p []byte) (int, error) {
	if cr.off < len(cr.buf) {
		n := copy(p, cr.buf[cr.off:])
		cr.off += n
		if cr.off >= len(cr.buf) {
			cr.buf = nil
			cr.off = 0
		}
		return n, nil
	}

	var lenBuf [chunkLenSize]byte
	if _, err := io.ReadFull(cr.r, lenBuf[:]); err != nil {
		return 0, err
	}
	plainLen := binary.BigEndian.Uint32(lenBuf[:])

	nonce := make([]byte, cr.aead.NonceSize())
	if _, err := io.ReadFull(cr.r, nonce); err != nil {
		return 0, fmt.Errorf("read nonce: %w", err)
	}

	tagSize := cr.aead.Overhead()
	ciphertext := make([]byte, int(plainLen)+tagSize)
	if _, err := io.ReadFull(cr.r, ciphertext); err != nil {
		return 0, fmt.Errorf("read ciphertext: %w", err)
	}

	plain, err := cr.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, fmt.Errorf("decrypt chunk: %w", err)
	}

	cr.buf = plain
	cr.off = 0

	n := copy(p, cr.buf)
	cr.off = n
	return n, nil
}
