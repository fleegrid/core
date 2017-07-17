package core

import (
	"crypto/cipher"
)

// DummyAEAD a dummy AEAD
type dummyAEAD struct{}

func (d *dummyAEAD) NonceSize() int {
	return 16
}

func (d *dummyAEAD) Overhead() int {
	return 0
}

func (d *dummyAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if dst != nil {
		copy(plaintext, dst)
	}
	return plaintext
}

func (d *dummyAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if dst != nil {
		copy(ciphertext, dst)
	}
	return ciphertext, nil
}

// DummyCipher a non-encryption cipher for debug purpose
type DummyCipher struct{}

// NewDummyCipher creates a new dummy cipher
func NewDummyCipher(b []byte, k int) (Cipher, error) {
	return &DummyCipher{}, nil
}

// KeySize for DummyCipher
func (d *DummyCipher) KeySize() int {
	return 32
}

// SaltSize for DummyCipher
func (d *DummyCipher) SaltSize() int {
	return 32
}

// NonceSize for DummyCipher
func (d *DummyCipher) NonceSize() int {
	return 16
}

// CreateAEAD for DummyCipher
func (d *DummyCipher) CreateAEAD(salt []byte) (cipher.AEAD, error) {
	return &dummyAEAD{}, nil
}
