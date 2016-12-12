package ezcrypt

import (
	"bytes"
	"crypto/rand"
	"testing"
	"io"
	"fmt"
)

type badKey struct{}

var _ Key = &badKey{}

func (*badKey) Bytes() *[KeySize]byte {
	return nil
}
func (*badKey) Slice() []byte {
	return []byte{}
}

func (*badKey) 	Encrypt(data []byte, in io.Reader) ([]byte, error) {
	return nil, fmt.Errorf("Bad Key!");
}

func (*badKey)	Decrypt(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("Bad Key!");
}
func (*badKey) Store(file string) error {
	return fmt.Errorf("Bad Key!");
}

var (
	m = []byte("Ezcrypt is awesome!")
)

func TestSymetric(t *testing.T) {
	k, err := GenerateKey(rand.Reader)

	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}

	bad_k, err := GenerateKey(rand.Reader)

	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}

	_, err = encrypt(m, k, &errReader{})

	if err == nil {
		t.Fatalf("encrypted with bad reader")
	}

	ct, err := encrypt(m, k, rand.Reader)

	if err != nil {
		t.Fatalf("encrypt: %s", err)
	}

	if bytes.Equal(ct, m) {
		t.Fatalf("WTF?")
	}

	tcs := []struct {
		test string
		k    Key
		ok   bool
	}{
		{
			test: "success",
			k:    k,
			ok:   true,
		},
		{
			test: "bad k",
			k:    bad_k,
			ok:   false,
		},
	}

	for _, tc := range tcs {
		d, err := decrypt(ct, tc.k)

		if tc.ok {
			if err != nil {
				t.Fatalf("Error: %s", tc.test)
			}

			if !bytes.Equal(m, d) {
				t.Fatalf("WTF: %s Expected: %v Got: %v", tc.test, m, d)
			}
		} else {
			if err == nil {
				t.Fatalf("Error: %s", tc.test)
			}
			if bytes.Equal(m, d) {
				t.Fatalf("WTF: %s", tc.test)
			}
		}
	}
}

func TestSymetricEncryptDefences(t *testing.T) {
	k, err := GenerateKey(rand.Reader)

	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}

	tcs := []struct {
		m []byte
		k Key
		r io.Reader
	}{
		{
			m: []byte{},
			k: k,
			r: rand.Reader,
		},
		{
			m: m,
			k: nil,
			r: rand.Reader,
		},
		{
			m: m,
			k: k,
			r: nil,
		},
		{
			m: m,
			k: k,
			r: &errReader{},
		},
	}

	for _, tc := range tcs {
		_, err = encrypt(tc.m, tc.k, tc.r)
		if err == nil {
			t.Errorf("No Error: %#v", tc)
		}
	}
}

func TestSymetricDecryptDefences(t *testing.T) {
	k, err := GenerateKey(rand.Reader)

	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}

	m, err := encrypt(m, k, rand.Reader)

	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	tcs := []struct {
		m []byte
		k Key
	}{
		{
			m: []byte(""),
			k: k,
		},
		{
			m: m,
			k: nil,
		},
		{
			m: m,
			k: &badKey{},
		},
	}

	for _, tc := range tcs {
		_, err = decrypt(tc.m, tc.k)
		if err == nil {
			t.Errorf("No Error: %#v", tc)
		}
	}
}
