package exiles

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
)

// PayloadMaxSize is the maximum size of payload in bytes.
const PayloadMaxSize = 0x3FFF // 16*1024 - 1

// StreamWriter encrypt data and write to underlying io.Writer
type StreamWriter struct {
	io.Writer
	cipher.AEAD
	buf   []byte
	nonce []byte
}

// NewStreamWriter create a StreamWriter
func NewStreamWriter(w io.Writer, a cipher.AEAD) *StreamWriter {
	return &StreamWriter{
		Writer: w,
		AEAD:   a,
		buf:    make([]byte, 2+a.Overhead()+PayloadMaxSize+a.Overhead()),
		nonce:  make([]byte, a.NonceSize()),
	}
}

// Write encrypt and write bytes
func (w *StreamWriter) Write(b []byte) (int, error) {
	n, err := w.ReadFrom(bytes.NewReader(b))
	return int(n), err
}

// ReadFrom encrypt and write bytes from a io.Reader
func (w *StreamWriter) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		buf := w.buf
		pBuf := buf[2+w.Overhead() : 2+w.Overhead()+PayloadMaxSize]
		nr, er := r.Read(pBuf)

		if nr > 0 {
			n += int64(nr)
			buf = buf[:2+w.Overhead()+nr+w.Overhead()]
			pBuf = pBuf[:nr]
			buf[0], buf[1] = byte(nr>>8), byte(nr) // Big-endian payload size
			w.Seal(buf[:0], w.nonce, buf[:2], nil)
			increaseNonce(w.nonce)

			w.Seal(pBuf[:0], w.nonce, pBuf, nil)
			increaseNonce(w.nonce)

			_, ew := w.Writer.Write(buf)
			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // EOF should be OK
				err = er
			}
			break
		}
	}

	return
}

// StreamReader reads a encrypted io.Reader and decrypt
type StreamReader struct {
	io.Reader
	cipher.AEAD
	buf    []byte
	nonce  []byte
	debris []byte
}

// NewStreamReader Create a New StreamReader
func NewStreamReader(r io.Reader, a cipher.AEAD) *StreamReader {
	return &StreamReader{
		Reader: r,
		AEAD:   a,
		buf:    make([]byte, PayloadMaxSize+a.Overhead()),
		nonce:  make([]byte, a.NonceSize()),
	}
}

func (r *StreamReader) internalRead() (int, error) {
	// decrypt payload size
	buf := r.buf[:2+r.Overhead()]
	_, err := io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increaseNonce(r.nonce)
	if err != nil {
		return 0, err
	}

	size := (int(buf[0])<<8 + int(buf[1])) & PayloadMaxSize

	// decrypt payload
	buf = r.buf[:size+r.Overhead()]
	_, err = io.ReadFull(r.Reader, buf)
	if err != nil {
		return 0, err
	}

	_, err = r.Open(buf[:0], r.nonce, buf, nil)
	increaseNonce(r.nonce)
	if err != nil {
		return 0, err
	}

	return size, nil
}

// Read reads from the embedded io.Reader, decrypts and writes to b.
func (r *StreamReader) Read(b []byte) (int, error) {
	// copy decrypted bytes (if any) from previous record first
	if len(r.debris) > 0 {
		n := copy(b, r.debris)
		r.debris = r.debris[n:]
		return n, nil
	}

	n, err := r.internalRead()
	m := copy(b, r.buf[:n])
	if m < n { // insufficient len(b), keep debris for next read
		r.debris = r.buf[m:n]
	}
	return m, err
}

// WriteTo reads from underlaying io.Reader, write everything to io.Writer
func (r *StreamReader) WriteTo(w io.Writer) (n int64, err error) {
	// fix previous debris
	for len(r.debris) > 0 {
		nw, ew := w.Write(r.debris)
		r.debris = r.debris[nw:]
		n += int64(nw)
		if ew != nil {
			return n, ew
		}
	}

	for {
		nr, er := r.internalRead()
		if nr > 0 {
			nw, ew := w.Write(r.buf[:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				break
			}
		}

		if er != nil {
			if er != io.EOF { // EOF is OK
				err = er
			}
			break
		}
	}

	return n, err
}

// StreamConn wraps a net.Conn with automatically encryption and decryption
type StreamConn struct {
	net.Conn
	Cipher
	w *StreamWriter
	r *StreamReader
}

// NewStreamConn create a new StreamConn
func NewStreamConn(conn net.Conn, c Cipher) *StreamConn {
	return &StreamConn{
		Conn:   conn,
		Cipher: c,
	}
}

func (c *StreamConn) initReader() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}

	a, err := c.CreateAEAD(salt)
	if err != nil {
		return err
	}

	c.r = NewStreamReader(c.Conn, a)
	return nil
}

func (c *StreamConn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

// WriteTo see StreamReader#WriteTo
func (c *StreamConn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

func (c *StreamConn) initWriter() error {
	salt := make([]byte, c.SaltSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	a, err := c.CreateAEAD(salt)
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(salt)
	if err != nil {
		return err
	}
	c.w = NewStreamWriter(c.Conn, a)
	return nil
}

func (c *StreamConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

// ReadFrom see StreamWriter#ReadFrom
func (c *StreamConn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}

// increase little-endian nonce with unspecified length, preventing overflow
func increaseNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
