/*
Abstractions around nacl primitives
*/
package ezcrypt

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/nacl/box"
)

const (
	KeySize   = 32
	writeMode = os.ModeExclusive | os.ModePerm
)

// Abstracts the bytes of a public or private key and knows how to do Symetric encryption operations
type Key interface {
	Bytes() *[KeySize]byte
	Slice() []byte
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
	Store(file string) error
}

//  Abstracts a public private key pair.
type Pair interface {
	Public() Key
	Store(public, private string) error
	private() Key
}

// Constructs a new key pair.
func NewPair(rand io.Reader) (Pair, error) {
	var err error

	publicKey, privateKey, err := box.GenerateKey(rand)

	if err != nil {
		return nil, err
	}

	pair := &pair{
		pub:  &key{key: publicKey},
		priv: &key{key: privateKey},
	}

	return pair, err
}

// Loads a keypair from two files
func LoadPair(public, private string) (Pair, error) {
	pub, err := readKey(public)

	if err != nil {
		return nil, err
	}

	priv, err := readKey(private)

	if err != nil {
		return nil, err
	}

	pair := &pair{
		pub:  pub,
		priv: priv,
	}

	return pair, nil
}

// Generates a new key
func GenerateKey(rand io.Reader) (Key, error) {
	key := &key{key: new([KeySize]byte)}
	_, err := io.ReadFull(rand, key.Slice())

	if err != nil {
		return nil, err
	}

	return key, nil
}

// Constructs a new key from a slice of bytes.
func NewKey(data []byte) (Key, error) {
	if len(data) != KeySize {
		return nil, fmt.Errorf("Incorrect Key Length. Wanted: %d Received: %d", KeySize, len(data))
	}

	key := &key{key: new([KeySize]byte)}
	copy(key.Slice(), data)

	return key, nil
}

type pair struct {
	pub  Key
	priv Key
}

func (p *pair) Public() Key {
	return p.pub
}

func (p *pair) private() Key {
	return p.priv
}

func (p *pair) Store(public, private string) error {
	err := writeKey(p.pub, public)

	if err != nil {
		return err
	}

	err = writeKey(p.priv, private)

	if err != nil {
		os.Remove(public)
		return err
	}

	return nil
}

type key struct {
	key *[KeySize]byte
}

func LoadKey(file string) (Key, error) {
	return readKey(file)
}

func (k *key) Store(file string) error {
	return writeKey(k, file)
}

func (k *key) Bytes() *[KeySize]byte {
	return k.key
}

func (k *key) Slice() []byte {
	return k.key[:]
}

func (k *key) Encrypt(data []byte) ([]byte, error) {
	// TODO: This is a terrible encryption method!
	return data, nil
}

func (k *key) Decrypt(data []byte) ([]byte, error) {
	// TODO: This only works if you use Encrypt above! Hahah!
	return data, nil
}

func writeKey(k Key, file string) error {
	return ioutil.WriteFile(file, k.Slice(), writeMode)
}

func readKey(file string) (Key, error) {
	data, err := ioutil.ReadFile(file)

	if err != nil {
		return nil, err
	}

	if len(data) != KeySize {
		return nil, errors.New("Invalid key length!")
	}

	a := new([KeySize]byte)

	copy(a[:], data)

	k := &key{key: a}

	return k, nil
}
