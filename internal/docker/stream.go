package docker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Demux copies the output of a multiplexed attach stream to w, stdout and
// stderr alike, in the order the daemon sent them, until the stream ends. A
// container without a TTY is streamed as frames of an 8-byte header (the
// stream, three zero bytes, and the payload's length, big-endian) and the
// payload.
func Demux(r io.Reader, w io.Writer) error {
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("docker: read stream header: %w", err)
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		if _, err := io.CopyN(w, r, n); err != nil {
			return fmt.Errorf("docker: read stream frame: %w", err)
		}
	}
}
