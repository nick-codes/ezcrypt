package ezcrypt

import (
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	overhead  = box.Overhead + nonceSize
)

func checkEncrypt(m []byte, k Key) error {
	if len(m) == 0 {
		return fmt.Errorf("Zero length message.")
	}
	if k == nil {
		return fmt.Errorf("No key")
	}
	if k.Bytes() == nil {
		return fmt.Errorf("No data in key")
	}

	return nil
}

func encrypt(m []byte, k Key, in io.Reader) ([]byte, error) {
	err := checkEncrypt(m, k)

	if err != nil {
		return nil, err
	}

	if in == nil {
		return nil, fmt.Errorf("No random source")
	}

	n, err := generateNonce(in)

	if err != nil {
		return nil, err
	}

	ret := secretbox.Seal(n.Slice(), m, n.Bytes(), k.Bytes())

	return ret, nil
}

func checkMessageLength(m []byte) error {
	if len(m) <= (overhead) {
		return fmt.Errorf("Message too short!")
	}
	return nil
}

func checkDecrypt(m []byte, k Key) error {
	err := checkMessageLength(m)
	if err != nil {
		return err
	}
	return checkEncrypt(m, k)
}

func decrypt(m []byte, k Key) ([]byte, error) {
	err := checkDecrypt(m, k)

	if err != nil {
		return nil, err
	}

	// error is not possible here because checkDecrypt validated message length
	n, _ := newNonce(m)
	
	out := make([]byte, 0, len(m)-overhead)

	ret, ok := secretbox.Open(out, m[nonceSize:], n.Bytes(), k.Bytes())

	if !ok {
		return nil, fmt.Errorf("Failed to decrypt message.")
	}

	return ret, nil
}
