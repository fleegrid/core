package exiles

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"io"
	"log"
	"strconv"
)

// ErrBadKeyLength error when key length is bad
type ErrBadKeyLength int

func (e ErrBadKeyLength) Error() string {
	return "Bad key length: " + strconv.Itoa(int(e))
}

// HKDFInfo pre-defined HKDF info
var HKDFInfo = []byte("ss-subkey")

// Cipher represents a AEAD cipher
type Cipher interface {
	// size of key
	KeySize() int
	// size of salt
	SaltSize() int
	// size of nonce
	NonceSize() int
	// tag size
	TagSize() int
	// create a AEAD with given salt
	CreateAEAD(salt []byte) (cipher.AEAD, error)
}

// ExpandPassword expand password with HKDF_SHA1
func ExpandPassword(in, salt, out []byte) {
	r := hkdf.New(sha1.New, in, salt, HKDFInfo)
	_, err := io.ReadFull(r, out)
	if err != nil {
		// should never happened
		log.Fatal(err)
	}
}

// ChapoCipher is for ChaCha20-Poly1305
type ChapoCipher struct {
	key []byte
}

// NewChapoCipher create a new ChapoCipher base on a key string
func NewChapoCipher(key []byte) (*ChapoCipher, error) {
	return &ChapoCipher{key: key}, nil
}

// KeySize for ChaCha20-Poly1305
func (c *ChapoCipher) KeySize() int {
	return chacha20poly1305.KeySize
}

// SaltSize for ChaCha20-Poly1305
func (c *ChapoCipher) SaltSize() int {
	return 32
}

// NonceSize for ChaCha20-Poly1305
func (c *ChapoCipher) NonceSize() int {
	return chacha20poly1305.NonceSize
}

// TagSize for ChaCha20-Poly1305
func (c *ChapoCipher) TagSize() int {
	return 16
}

// CreateAEAD for ChaCha20-Poly1305
func (c *ChapoCipher) CreateAEAD(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, c.KeySize())
	ExpandPassword(c.key, salt, subkey)
	return chacha20poly1305.New(subkey)
}

// AESGCMCipher is for AES_XXX_GCM
type AESGCMCipher struct {
	key  []byte
	size int
}

// NewAESGCMCipher create a new AES_XXX_GCM cipher
// one of 16, 24, or 32 to select AES-128/196/256-GCM.
func NewAESGCMCipher(key []byte, size int) (*AESGCMCipher, error) {
	return &AESGCMCipher{key: key[:size], size: size}, nil
}

// KeySize for AES-GCM
func (c *AESGCMCipher) KeySize() int {
	return c.size
}

// SaltSize for AES-GCM
func (c *AESGCMCipher) SaltSize() int {
	return c.size
}

// NonceSize for AES-GCM
func (c *AESGCMCipher) NonceSize() int {
	return 12
}

// TagSize for AES-GCM
func (c *AESGCMCipher) TagSize() int {
	return 16
}

// CreateAEAD for AESGCM
func (c *AESGCMCipher) CreateAEAD(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, c.KeySize())
	ExpandPassword(c.key, salt, subkey)
	blk, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}
