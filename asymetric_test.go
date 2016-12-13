package ezcrypt

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

var (
	nilPriv = &pair{
		priv: nil,
	}
	nilPrivData = &pair{
		priv: &badKey{},
	}
)

func TestAsymetricEncrypt(t *testing.T) {
	p, err := GeneratePair(rand.Reader)

	if err != nil {
		t.Fatalf("GeneratePair Failed: %s", err)
	}

	tcs := []struct {
		t  string
		m  []byte
		k  Key
		p  Pair
		r  io.Reader
		ok bool
	}{
		{
			t:  "ok",
			m:  m,
			k:  p.Public(),
			p:  p,
			r:  rand.Reader,
			ok: true,
		},
		{
			t: "nil message",
			k: p.Public(),
			p: p,
			r: rand.Reader,
		},
		{
			t: "nil public",
			m: m,
			p: p,
			r: rand.Reader,
		},
		{
			t: "bad public",
			m: m,
			k: &badKey{},
			p: p,
			r: rand.Reader,
		},
		{
			t: "nil pair",
			m: m,
			k: p.Public(),
			r: rand.Reader,
		},
		{
			t: "nil private",
			m: m,
			k: p.Public(),
			p: nilPriv,
			r: rand.Reader,
		},
		{
			t: "nil private data",
			m: m,
			k: p.Public(),
			p: nilPrivData,
			r: rand.Reader,
		},
		{
			t: "nil rand",
			m: m,
			k: p.Public(),
			p: p,
		},
	}

	for _, tc := range tcs {
		ct, err := encryptAsym(tc.m, tc.k, tc.p, tc.r)

		if tc.ok {
			if err != nil {
				t.Errorf("Error: %s : %s", tc.t, err)
			} else {
				if bytes.Equal(m, ct) {
					t.Fatalf("WTF?")
				}
			}
		} else {
			if err == nil {
				t.Errorf("No Error: %s", tc.t)
			}
		}
	}
}

func TestAsymetricDecrypt(t *testing.T) {
	ap, err := GeneratePair(rand.Reader)

	if err != nil {
		t.Fatalf("GeneratePair Failed: %s", err)
	}

	bp, err := GeneratePair(rand.Reader)

	if err != nil {
		t.Fatalf("GeneratePair Failed: %s", err)
	}

	cp, err := GeneratePair(rand.Reader)

	if err != nil {
		t.Fatalf("GeneratePair Failed: %s", err)
	}

	ct, err := encryptAsym(m, ap.Public(), bp, rand.Reader)

	if err != nil {
		t.Errorf("Encrypt failed: %s", err)
	}

	if bytes.Equal(m, ct) {
		t.Fatalf("WTF?")
	}

	tcs := []struct {
		t  string
		m  []byte
		k  Key
		p  Pair
		ok bool
	}{
		{
			t:  "ok",
			m:  ct,
			k:  bp.Public(),
			p:  ap,
			ok: true,
		},
		{
			t: "nil message",
			k: bp.Public(),
			p: ap,
		},
		{
			t: "short message",
			m: []byte("short"),
			k: bp.Public(),
			p: ap,
		},
		{
			t: "nil public",
			m: ct,
			p: ap,
		},
		{
			t: "nil public data",
			m: ct,
			k: &badKey{},
			p: ap,
		},
		{
			t: "nil pair",
			m: ct,
			k: bp.Public(),
		},
		{
			t: "nil private",
			m: ct,
			k: bp.Public(),
			p: nilPriv,
		},
		{
			t: "nil private data",
			m: ct,
			k: bp.Public(),
			p: nilPrivData,
		},
		{
			t: "wrong private",
			m: ct,
			k: bp.Public(),
			p: cp,
		},
		{
			t: "wrong public",
			m: ct,
			k: cp.Public(),
			p: ap,
		},
	}

	for _, tc := range tcs {
		d, err := decryptAsym(tc.m, tc.k, tc.p)

		if tc.ok {
			if err != nil {
				t.Errorf("Error: %s : %s", tc.t, err)
			} else {
				if !bytes.Equal(m, d) {
					t.Errorf("Decrypt Failed: %s : %s : %s", tc.t, m, d)
				}
			}
		} else {
			if err == nil {
				t.Errorf("No error: %s", tc.t)
			} else {
				if bytes.Equal(m, d) {
					t.Errorf("WTF?: %s", tc.t)
				}
			}
		}
	}
}
