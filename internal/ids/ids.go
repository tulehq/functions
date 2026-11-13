// Package ids makes the random identifiers the service hands out.
package ids

import (
	"crypto/rand"
	"encoding/hex"
)

// UUID returns a random (version 4) UUID, the form Lambda's request IDs,
// revision IDs and event source mapping UUIDs take. crypto/rand.Read never
// fails, so neither does this.
func UUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Hex returns n random bytes as lowercase hex.
func Hex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
