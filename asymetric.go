package ezcrypt

import (
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

func checkAsym(m []byte, k Key, p Pair) error {
	err := checkEncrypt(m, k)

	if err != nil {
		return err
	}

	if p == nil {
		return fmt.Errorf("Pair is missing.")
	}

	if p.private() == nil {
		return fmt.Errorf("Pair is missing private key.")
	}

	if p.private().Bytes() == nil {
		return fmt.Errorf("Private key is missing data.")
	}

	return nil
}

func encryptAsym(m []byte, k Key, p Pair, in io.Reader) ([]byte, error) {
	err := checkAsym(m, k, p)

	if err != nil {
		return nil, err
	}

	n, err := generateNonce(in)

	if err != nil {
		return nil, err
	}

	ret := box.Seal(n.Slice(), m, n.Bytes(), k.Bytes(), p.private().Bytes())

	return ret, nil
}

func checkDecryptAsym(m []byte, k Key, p Pair) error {
	err := checkAsym(m, k, p)

	if err != nil {
		return err
	}

	if len(m) <= overhead {
		return fmt.Errorf("Message is too short.")
	}

	return nil
}

func decryptAsym(m []byte, k Key, p Pair) ([]byte, error) {
	err := checkDecryptAsym(m, k, p)

	if err != nil {
		return nil, err
	}

	n := newNonce(m)

	b := make([]byte, 0, len(m)-overhead)

	ret, ok := box.Open(b, m[nonceSize:], n.Bytes(), k.Bytes(), p.private().Bytes())

	if !ok {
		return nil, fmt.Errorf("Decryption failed.")
	}

	return ret, nil
}
