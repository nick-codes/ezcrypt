package ezcrypt

import (
	"testing"
	"bytes"
)

var (
	nonceBytes = []byte("abcdefghizklmnopqrstuvwx")
)

func TestNonce(t *testing.T) {
	_, err := newNonce([]byte(""))

	if err == nil {
		t.Fatalf("Expected error");
	}

	b, err := newNonce(nonceBytes);

	if !bytes.Equal(b.Slice(), nonceBytes) {
		t.Fatalf("Nonce mismatch.")
	}

	_, err = generateNonce(nil)

	if err == nil {
		t.Fatalf("Expected error");
	}
}
