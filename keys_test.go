package ezcrypt

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

const (
	pubFile     = "public.key"
	privFile    = "private.key"
	invalidFile = "invalid.key"
	dotFile     = "."
	secretFile  = "secret.key"
)

type errReader struct{}

func (*errReader) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("Error!")
}

func pairsAreEqual(a Pair, b Pair) bool {
	if bytes.Equal(a.Public().Slice(), b.Public().Slice()) && bytes.Equal(a.private().Slice(), b.private().Slice()) {
		return true
	}
	return false
}

func TestKey(t *testing.T) {
	temp, err := ioutil.TempDir(os.TempDir(), "keys_test")

	if err != nil {
		t.Fatalf("Failed to make temp: %s", err)
	}

	defer removeTemp(t, temp)

	invalid := path.Join(temp, invalidFile)
	secret := path.Join(temp, secretFile)

	_, err = GenerateKey(&errReader{})

	if err == nil {
		t.Fatalf("Failed to bork with bad rand source.")
	}

	k, err := GenerateKey(rand.Reader)

	if err != nil {
		t.Fatalf("Generate Key Failed: %s", err)
	}

	err = k.Store(secret)

	if err != nil {
		t.Fatalf("Store Key Failed: %s", err)
	}

	k2, err := LoadKey(invalid)

	if err == nil {
		t.Fatalf("Read invalid key")
	}

	k2, err = LoadKey(secret)

	if err != nil {
		t.Fatalf("Failed to read secret.")
	}

	err = k2.Store(temp)

	if err == nil {
		t.Fatalf("Stored a key as a directory?")
	}

	ioutil.WriteFile(invalid, []byte("invalid"), writeMode)

	_, err = LoadKey(invalid)

	if err == nil {
		t.Fatalf("Loaded invalid key!")
	}

	ct, err := k.Encrypt(m, rand.Reader)

	if err != nil {
		t.Fatalf("Failed to Encrypt: %s", err)
	}

	if bytes.Equal(m, ct) {
		t.Fatalf("WTF!")
	}

	dec, err := k2.Decrypt(ct)

	if !bytes.Equal(m, dec) {
		t.Fatalf("Decrypt failed: expected: %s != %s", pubFile, dec)
	}

	_, err = k.Encrypt([]byte(pubFile), &errReader{})

	if err == nil {
		t.Fatalf("Encrypted with bad reader")
	}

}

func TestNewKey(t *testing.T) {
	tests := []struct {
		d  []byte
		ok bool
	}{
		{
			d:  []byte("abcdefghijklmnopqrstuvwxyz012345"),
			ok: true,
		},
		{
			d:  make([]byte, 0),
			ok: false,
		},
		{
			d:  make([]byte, KeySize+1),
			ok: false,
		},
		{
			d:  make([]byte, KeySize-1),
			ok: false,
		},
		{
			d:  nil,
			ok: false,
		},
	}

	for _, tc := range tests {
		key, err := NewKey(tc.d)
		if tc.ok {
			if err != nil {
				t.Fatalf("Got %s: len: %d", err, len(tc.d))
			}
			if !bytes.Equal(tc.d[:], key.Bytes()[:]) {
				t.Fatalf("wrong byte data.")
			}
			if !bytes.Equal(tc.d[:], key.Slice()) {
				t.Fatalf("wrong slice data.")
			}
		} else {
			if err == nil {
				t.Fatalf("Expected error: %d", len(tc.d))
			}
		}
	}
}

func TestPair(t *testing.T) {
	temp, err := ioutil.TempDir(os.TempDir(), "test_pair")

	if err != nil {
		t.Fatalf("Failed to make temp: %s", err)
	}

	defer removeTemp(t, temp)

	invalid := path.Join(temp, invalidFile)
	pub := path.Join(temp, pubFile)
	priv := path.Join(temp, privFile)

	err = ioutil.WriteFile(invalid, []byte("short"), writeMode)

	if err != nil {
		t.Fatalf("Failed to write invalid key for test.")
	}

	_, err = GeneratePair(&errReader{})

	if err == nil {
		t.Fatalf("Failed to bork with bad rand source.")
	}

	pair, err := GeneratePair(rand.Reader)

	if err != nil {
		t.Fatalf("Failed to make pair: %s", err)
	}

	ct, err := pair.Encrypt(m, pair.Public(), rand.Reader)

	if err != nil {
		t.Fatalf("Encrypt failed: %s", err)
	}

	dt, err := pair.Decrypt(ct, pair.Public())

	if err != nil {
		t.Fatalf("Decrypt failed: %s", err)
	}

	if !bytes.Equal(m, dt) {
		t.Fatalf("Decrypted message wrong: %s", dt)
	}

	err = pair.Store(temp, priv)

	if err == nil {
		t.Fatalf("Stored pub as directory")
	}

	err = pair.Store(pub, temp)

	if err == nil {
		t.Fatalf("Stored priv as directory")
	}

	err = pair.Store(pub, priv)

	if err != nil {
		t.Fatalf("Failed store pair: %s", err)
	}

	_, err = LoadPair(pub, invalid)

	if nil == err {
		t.Fatalf("Read with invalid private key")
	}

	_, err = LoadPair(invalid, priv)

	if nil == err {
		t.Fatalf("Read with invalid public key")
	}

	p2, err := LoadPair(pub, priv)

	if !pairsAreEqual(pair, p2) {
		t.Fatalf("Loaded pair is not equal to the original.")
	}
}

func removeTemp(t *testing.T, temp string) {
	err := os.RemoveAll(temp)

	if err != nil {
		t.Fatalf("Failed to cleanup temp dir: %s", temp)
		t.Fail()
	}
}
