package core

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestDummyCipher(t *testing.T) {
	name := "dummy"
	c, _ := NewCipher("AEAD_DUMMY", "hello")

	plain := []byte("hello world!")
	salt := []byte("world")
	nonce := make([]byte, c.NonceSize())
	rand.Read(nonce)

	aead1, err := c.CreateAEAD(salt)
	if err != nil {
		t.Fatalf("%v: Failed to create AEAD; error: %v", name, err)
	}
	encrypted := aead1.Seal(nil, nonce, plain, nil)

	if !bytes.Equal(encrypted, plain) {
		t.Errorf("dummy result mismatch")
	}

	aead2, err := c.CreateAEAD(salt)
	if err != nil {
		t.Fatalf("%v: Failed to create AEAD; error: %v", name, err)
	}
	decrypted, err := aead2.Open(nil, nonce, plain, nil)
	if err != nil {
		t.Fatalf("%v: Failed to decrypt; error: %v", name, err)
	}
	if !bytes.Equal(plain, decrypted) {
		t.Fatalf("%v: Result mismatch", name)
	}
}
