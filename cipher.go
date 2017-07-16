package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"io"
	"log"
	"strconv"
)

// CipherDescriptor describes ciphers
type CipherDescriptor struct {
	KeySize       int
	CipherFactory func([]byte, int) (Cipher, error)
}

var (
	// SupportedCipherNames names of supported ciphers
	SupportedCipherNames = []string{
		"AEAD_CHACHA20_POLY1305",
		"AEAD_AES_128_GCM",
		"AEAD_AES_192_GCM",
		"AEAD_AES_256_GCM",
	}
	// SupportedCiphers array of supported ciphers
	SupportedCiphers = map[string]*CipherDescriptor{
		"AEAD_CHACHA20_POLY1305": {
			KeySize:       32,
			CipherFactory: NewChapoCipher,
		},
		"AEAD_AES_128_GCM": {
			KeySize:       16,
			CipherFactory: NewAESGCMCipher,
		},
		"AEAD_AES_192_GCM": {
			KeySize:       24,
			CipherFactory: NewAESGCMCipher,
		},
		"AEAD_AES_256_GCM": {
			KeySize:       32,
			CipherFactory: NewAESGCMCipher,
		},
	}
)

// BadKeyLengthError error when key length is bad
type BadKeyLengthError int

func (e BadKeyLengthError) Error() string {
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
	// create a AEAD with given salt
	CreateAEAD(salt []byte) (cipher.AEAD, error)
}

// NewCipher create a new Cipher with name and password
func NewCipher(name, password string) (Cipher, error) {
	desc := SupportedCiphers[name]
	if desc == nil {
		// not possible, config.go should handled it
		log.Fatal("Cipher " + name + " is not supported")
	}
	key := DeriveMasterKey(password, desc.KeySize)
	return desc.CipherFactory(key, desc.KeySize)
}

// DeriveMasterKey derive master key from password string
func DeriveMasterKey(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}

// DeriveSubkey expand password with HKDF_SHA1
func DeriveSubkey(master, salt, out []byte) {
	r := hkdf.New(sha1.New, master, salt, HKDFInfo)
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
func NewChapoCipher(key []byte, size int) (Cipher, error) {
	if size != chacha20poly1305.KeySize {
		log.Fatalf("keySize of chacha20-poly1305 should be fixed %v\n", chacha20poly1305.KeySize)
	}
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

// CreateAEAD for ChaCha20-Poly1305
func (c *ChapoCipher) CreateAEAD(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, c.KeySize())
	DeriveSubkey(c.key, salt, subkey)
	return chacha20poly1305.New(subkey)
}

// AESGCMCipher is for AES_XXX_GCM
type AESGCMCipher struct {
	key  []byte
	size int
}

// NewAESGCMCipher create a new AES_XXX_GCM cipher
// one of 16, 24, or 32 to select AES-128/196/256-GCM.
func NewAESGCMCipher(key []byte, size int) (Cipher, error) {
	return &AESGCMCipher{key: key, size: size}, nil
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

// CreateAEAD for AESGCM
func (c *AESGCMCipher) CreateAEAD(salt []byte) (cipher.AEAD, error) {
	subkey := make([]byte, c.KeySize())
	DeriveSubkey(c.key, salt, subkey)
	blk, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}
