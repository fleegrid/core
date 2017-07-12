package exiles

import (
	"encoding/hex"
	"math/rand"
	"net"
	"testing"
)

const packetAddr = ":12302"
const packetAddr2 = ":12303"

func randomPacketString() string {
	bytes := make([]byte, rand.Intn(PayloadMaxSize/16))
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func TestPacketConn(t *testing.T) {

	// create cipher
	c, err := NewCipher("AEAD_CHACHA20_POLY1305", "hello")
	if err != nil {
		t.Fatal("Cannot create Cipher")
	}

	// create a server with unix domain socket
	laddr, err := net.ResolveUDPAddr("udp", packetAddr)
	laddr2, err2 := net.ResolveUDPAddr("udp", packetAddr2)
	raddr, err3 := net.ResolveUDPAddr("udp", "127.0.0.1"+packetAddr)

	if err != nil || err2 != nil || err3 != nil {
		t.Fatalf("Cannot resolve UDP addr: %v, %v, %v\n", err, err2, err3)
	}

	sn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatal("Cannot listen socket")
	}

	sconn, err := NewPacketConn(sn, c)
	if err != nil {
		t.Fatalf("Cannot create PacketConn: %v\n", err)
	}

	res := ""

	read := make(chan bool, 1)

	go func() {
		buf := make([]byte, PacketMaxSize)
		for {
			l, _, e := sconn.ReadFrom(buf)
			if e != nil {
				break
			} else {
				res = string(buf[:l])
			}
			read <- true
		}
	}()

	for i := 0; i < 100; i++ {
		str := randomPacketString()

		cn, err := net.ListenUDP("udp", laddr2)
		if err != nil {
			t.Fatalf("Can't send UDP:%v\n", err)
		}

		cconn, err := NewPacketConn(cn, c)
		if err != nil {
			t.Fatalf("Can't create PacketConn:%v\n", err)
		}

		_, err = cconn.WriteTo([]byte(str), raddr)
		if err != nil {
			t.Fatalf("Can't write PacketConn:%v\n", err)
		}
		cconn.Close()

		<-read

		if res != str {
			t.Fatal("str mismatch")
		}
	}

	sconn.Close()
}
