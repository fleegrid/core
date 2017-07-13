package fgcore

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
)

// PacketMaxSize usually 64k
const PacketMaxSize = 64 * 1024

// ErrPacketTooShort packet is too short for a valid encrypted packet
var ErrPacketTooShort = errors.New("short packet")

// all zero nonce for packet protocol
var _zeroNonce [128]byte

// SealPacket encrypts packet
func SealPacket(dst, plain []byte, ciph Cipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	salt := dst[:saltSize]
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	a, err := ciph.CreateAEAD(salt)
	if err != nil {
		return nil, err
	}

	if len(dst) < saltSize+len(plain)+a.Overhead() {
		return nil, io.ErrShortBuffer
	}
	b := a.Seal(dst[saltSize:saltSize], _zeroNonce[:a.NonceSize()], plain, nil)
	return dst[:saltSize+len(b)], nil
}

// OpenPacket decrypt packet
func OpenPacket(dst, src []byte, ciph Cipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	if len(src) < saltSize {
		return nil, ErrPacketTooShort
	}
	salt := src[:saltSize]
	a, err := ciph.CreateAEAD(salt)
	if err != nil {
		return nil, err
	}
	if len(src) < saltSize+a.Overhead() {
		return nil, ErrPacketTooShort
	}
	if saltSize+len(dst)+a.Overhead() < len(src) {
		return nil, io.ErrShortBuffer
	}
	b, err := a.Open(dst[:0], _zeroNonce[:a.NonceSize()], src[saltSize:], nil)
	return b, err
}

// PacketConn wraps a net.PacketConn with Cipher
type PacketConn struct {
	net.PacketConn
	Cipher
	sync.Mutex
	buf []byte
}

// NewPacketConn wraps a net.PacketConn with Cipher
func NewPacketConn(conn net.PacketConn, c Cipher) (*PacketConn, error) {
	return &PacketConn{PacketConn: conn, Cipher: c, buf: make([]byte, PacketMaxSize)}, nil
}

// WriteTo encrypts bytes and writes to underlaying net.PacketConn
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.Lock()
	defer c.Unlock()
	buf, err := SealPacket(c.buf, b, c)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(buf, addr)
	return len(b), err
}

// ReadFrom reads from underlaying net.PacketConn and decrypts
func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	b, err = OpenPacket(b, b[:n], c)
	return len(b), addr, err
}
