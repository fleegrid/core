package fgcore

import (
	"testing"
)

func TestParseConfig(t *testing.T) {
	// should error
	c, e := ParseConfigFromURL("http://sadfdasf")
	if c != nil || e != ErrBadScheme {
		t.Errorf("should fail on bad scheme; config: %v; error: %v", c, e)
	}
	c, e = ParseConfigFromURL("ss://hello")
	if c != nil || e != ErrMissingPasswd {
		t.Errorf("should fail on missing passwd; config: %v; error: %v", c, e)
	}
	c, e = ParseConfigFromURL("ss://what:what@hello")
	if c != nil || e != ErrBadCipher {
		t.Errorf("should fail on bad cipher; config: %v; error: %v", c, e)
	}
	// should ok
	c, e = ParseConfigFromURL("ss://what@hello")
	if c == nil || e != nil || c.Passwd != "what" || c.Cipher != SupportedCipherNames[0] {
		t.Errorf("should ok with default cipher; config: %v; error: %v", c, e)
	}
	c, e = ParseConfigFromURL("ss://chacha20-polY1305:what@hello")
	if c == nil || e != nil || c.Passwd != "what" || c.Cipher != "AEAD_CHACHA20_POLY1305" {
		t.Errorf("should ok with aliases; config: %v; error: %v", c, e)
	}
	c, e = ParseConfigFromURL("ss://AEAD_CHACHA20_POLY1305:what@hello")
	if c == nil || e != nil || c.Passwd != "what" || c.Cipher != "AEAD_CHACHA20_POLY1305" {
		t.Errorf("should ok with specified cipher; config: %v; error: %v", c, e)
	}
	c, e = ParseConfigFromURL("ss://cHACHA20-POLY1305:what@hello")
	if c == nil || e != nil || c.Passwd != "what" || c.Cipher != "AEAD_CHACHA20_POLY1305" {
		t.Errorf("should ok without AEAD_ prefix; config: %v; error: %v", c, e)
	}
}
