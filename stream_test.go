package exiles

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"testing"
)

const socketAddr = "/tmp/exiles-test-stream-conn-001.sock"

func randomString() string {
	bytes := make([]byte, PayloadMaxSize/2+rand.Intn(PayloadMaxSize/2))
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func TestStreamConn(t *testing.T) {

	// create cipher
	c, err := NewCipher("AEAD_CHACHA20_POLY1305", "hello")
	if err != nil {
		t.Fatalf("Cannot create Cipher")
	}

	// create a server with unix domain socket
	os.Remove(socketAddr)
	l, err := net.Listen("unix", socketAddr)
	if err != nil {
		t.Fatalf("Cannot listen socket")
	}

	sconnReady := make(chan bool, 1)

	var sconn *StreamConn

	// server side
	go func() {
		for {
			conn, err := l.Accept()
			if err == nil {
				go func() {
					sconn = NewStreamConn(conn, c)
					sconnReady <- true
				}()
			} else {
				break
			}
		}
	}()

	// client side
	for i := 0; i < 10; i++ {
		conn, err := net.Dial("unix", socketAddr)
		if err != nil {
			t.Fatal("Cannot dial socket")
		}

		cconn := NewStreamConn(conn, c)

		<-sconnReady

		str := randomString()

		go func() {
			cconn.ReadFrom(bytes.NewBufferString(str))
			cconn.Close()
		}()

		res, err := ioutil.ReadAll(sconn)

		if err != nil {
			t.Fatalf("Failed to read: %v", err)
		}

		if string(res) != str {
			t.Fatalf("Str mismatch")
		}

		sconn.Close()
	}

	l.Close()
}
