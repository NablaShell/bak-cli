package compress

import (
	"io"

	"github.com/klauspost/compress/zstd"
)

const DefaultLevel = 3

// Compress wraps a writer with zstd compression.
func Compress(w io.Writer) (io.WriteCloser, error) {
	return zstd.NewWriter(w,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithSingleSegment(true),
	)
}

// Decompress wraps a reader with zstd decompression.
func Decompress(r io.Reader) (io.ReadCloser, error) {
	dec, err := zstd.NewReader(r)
	if err != nil {
		return nil, err
	}
	return &decoderWrapper{dec}, nil
}

// decoderWrapper adapts *zstd.Decoder (Close()) to io.ReadCloser (Close() error).
type decoderWrapper struct {
	*zstd.Decoder
}

func (w *decoderWrapper) Close() error {
	w.Decoder.Close()
	return nil
}
