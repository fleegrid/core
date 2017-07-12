package exiles

import (
	"errors"
	"net/url"
	"strings"
)

var (
	// ErrBadURL URL is mal-formatted
	ErrBadURL = errors.New("bad ss:// url")
	// ErrBadScheme URL scheme is not 'ss'
	ErrBadScheme = errors.New("scheme is not 'ss' in ss:// url")
	// ErrBadCipher Cipher is not in SupportedCiphers
	ErrBadCipher = errors.New("cipher is not supported in ss:// url, only " + strings.Join(SupportedCiphers, ",") + " are supported")
	// ErrMissingPasswd password is missing from url
	ErrMissingPasswd = errors.New("password is not specified in ss:// url")
	// ErrMissingAddress host:port is missing from url
	ErrMissingAddress = errors.New("host:port is not specified in ss:// url")
)

// Config represents a basic configuration with address, cipher and password
type Config struct {
	// full address of ss protocol, for both server and client
	Address string
	// AEAD cipher, see https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml for names
	// default to "AEAD_CHACHA20_POLY1305"
	Cipher string
	// password
	Passwd string
}

// ParseConfigFromURL decode url string to Config
// Format:
//	ss://CIPHER:PASSWORD@ADDRESS:PORT
func ParseConfigFromURL(urlstr string) (*Config, error) {
	config := Config{}
	u, err := url.Parse(urlstr)
	// check URL
	if err != nil {
		return nil, ErrBadURL
	}
	// check scheme
	if u.Scheme != "ss" {
		return nil, ErrBadScheme
	}
	// check CIPHER:PASSWORD
	if u.User == nil {
		return nil, ErrMissingPasswd
	}
	// extract cipher, passwd
	passwd, ok := u.User.Password()
	if ok {
		// extract both cipher and passwd
		config.Cipher = u.User.Username()
		config.Passwd = passwd
	} else {
		// if no ciper, use default
		config.Cipher = SupportedCiphers[0]
		config.Passwd = u.User.Username()
	}
	// check is cipher supported
	config.Cipher, ok = ValidateCipher(config.Cipher)
	if !ok {
		return nil, ErrBadCipher
	}
	// check passwd
	if len(config.Passwd) == 0 {
		return nil, ErrMissingPasswd
	}
	// check address
	config.Address = u.Host
	if len(config.Address) == 0 {
		return nil, ErrMissingAddress
	}
	return &config, nil
}

// ValidateCipher resolve cipher alises and check if cipher is supported
func ValidateCipher(cipher string) (string, bool) {
	// to uppercase
	d := strings.ToUpper(cipher)
	// replace - with _
	d = strings.Replace(d, "-", "_", -1)
	// check supported ciphers
	for _, s := range SupportedCiphers {
		if s == d {
			return d, true
		}
	}
	// prepend "AEAD_" and try again
	d = "AEAD_" + d
	for _, s := range SupportedCiphers {
		if s == d {
			return d, true
		}
	}
	return "", false
}
