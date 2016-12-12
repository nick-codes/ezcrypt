package ezcrypt

import (
	"fmt"
	"io"
)

const (
	// Not sure why box doesn't export this
	nonceSize = 24
)

type nonce struct {
	d *[nonceSize]byte
}

func (n *nonce) Bytes() *[nonceSize]byte {
	return n.d
}

func (n *nonce) Slice() []byte {
	return n.d[:]
}

func newNonce(m []byte) (*nonce, error) {
	if len(m) < nonceSize {
		return nil, fmt.Errorf("Not enough data.")
	}

	n := &nonce{d: new([nonceSize]byte)}

	copy(n.Slice(), m[:nonceSize])

	return n, nil
}

func generateNonce(in io.Reader) (*nonce, error) {
	if in == nil {
		return nil, fmt.Errorf("No random source");
	}

	n := &nonce{d: new([nonceSize]byte)}

	_, err := io.ReadFull(in, n.Slice())

	if err != nil {
		return nil, err
	}

	return n, nil
}
