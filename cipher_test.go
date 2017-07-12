package exiles

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestNewCipher(t *testing.T) {
	c, err := NewCipher("AEAD_CHACHA20_POLY1305", "hello")
	if err != nil {
		t.Fatal("Failed to create cipher; error: %v", err)
	}
	_, ok := c.(*ChapoCipher)
	if !ok {
		t.Fatal("Should create a ChapoCipher")
	}
	c, err = NewCipher("AEAD_AES_128_GCM", "hello")
	if err != nil {
		t.Fatal("Failed to create cipher; error: %v", err)
	}
	_, ok = c.(*AESGCMCipher)
	if !ok {
		t.Fatal("Should create a AESGCMCipher")
	}
	if c.KeySize() != 16 {
		t.Fatal("Should be a AESGCMCipher with 16bit")
	}
}

func TestAllCiphers(t *testing.T) {
	for _, name := range SupportedCipherNames {
		testCipherEncryptDecrypt(name, t)
	}
}

func testCipherEncryptDecrypt(name string, t *testing.T) {
	c, err := NewCipher(name, "hello")
	if err != nil {
		t.Fatalf("%v: Failed to create cipher; error: %v", name, err)
	}

	plain := []byte("hello world!")
	salt := []byte("world")
	nonce := make([]byte, c.NonceSize())
	rand.Read(nonce)

	aead1, err := c.CreateAEAD(salt)
	if err != nil {
		t.Fatalf("%v: Failed to create AEAD; error: %v", name, err)
	}
	encrypted := aead1.Seal(nil, nonce, plain, nil)

	aead2, err := c.CreateAEAD(salt)
	if err != nil {
		t.Fatalf("%v: Failed to create AEAD; error: %v", name, err)
	}
	decrypted, err := aead2.Open(nil, nonce, encrypted, nil)
	if err != nil {
		t.Fatalf("%v: Failed to decrypt; error: %v", name, err)
	}
	if !bytes.Equal(plain, decrypted) {
		t.Fatalf("%v: Result mismatch", name)
	}
}
