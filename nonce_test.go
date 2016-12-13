package ezcrypt

import (
	"bytes"
	"testing"
)

var (
	nonceBytes = []byte("abcdefghizklmnopqrstuvwx")
)

func TestNonce(t *testing.T) {
	b := newNonce(nonceBytes)

	if !bytes.Equal(b.Slice(), nonceBytes) {
		t.Fatalf("Nonce mismatch.")
	}
}
