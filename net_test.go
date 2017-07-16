package core

import (
	"net"
	"testing"
)

func TestIPAssign(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("192.168.0.1/24")
	if err != nil {
		t.Errorf("cannot create a standard net")
	}
	n := NewNet(ipnet)
	var ip net.IP

	ip, err = n.Take()
	if err != nil {
		t.Errorf("cannot take a ip")
	}
	if !ip.Equal(net.ParseIP("192.168.0.1")) {
		t.Errorf("bad ip:%v:%v", n.IP.String(), ip.String())
	}

	ip, err = n.Take()
	if err != nil {
		t.Errorf("cannot take a ip")
	}
	if !ip.Equal(net.ParseIP("192.168.0.2")) {
		t.Errorf("bad ip:%v:%v", n.IP.String(), ip.String())
	}

	n.Remove(net.ParseIP("192.168.0.1"))

	ip, err = n.Take()
	if err != nil {
		t.Errorf("cannot take a ip")
	}
	if !ip.Equal(net.ParseIP("192.168.0.1")) {
		t.Errorf("bad ip:%v:%v", n.IP.String(), ip.String())
	}

	ip, err = n.Take()
	if err != nil {
		t.Errorf("cannot take a ip")
	}
	if !ip.Equal(net.ParseIP("192.168.0.3")) {
		t.Errorf("bad ip:%v:%v", n.IP.String(), ip.String())
	}

	n.Mark(net.ParseIP("192.168.0.4"))

	ip, err = n.Take()
	if err != nil {
		t.Errorf("cannot take a ip")
	}
	if !ip.Equal(net.ParseIP("192.168.0.5")) {
		t.Errorf("bad ip:%v:%v", n.IP.String(), ip.String())
	}

	for {
		ip0, err0 := n.Take()
		if err0 != nil {
			err = err0
			break
		}
		ip = ip0
	}

	if !ip.Equal(net.ParseIP("192.168.0.255")) {
		t.Errorf("bad last ip:%v:%v", n.IP.String(), ip.String())
	}
	if err != ErrOutOfIPs {
		t.Errorf("bad last error: %v", err)
	}
}
