package scanner

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sslclaw/internal/models"
	"time"
)

// TLS version constants
var tlsVersions = []struct {
	Name    string
	Version uint16
	Security models.SecurityLevel
}{
	{"TLS 1.3", tls.VersionTLS13, models.SecurityStrong},
	{"TLS 1.2", tls.VersionTLS12, models.SecurityAcceptable},
	{"TLS 1.1", tls.VersionTLS11, models.SecurityWeak},
	{"TLS 1.0", tls.VersionTLS10, models.SecurityWeak},
}

// detectProtocols checks which TLS/SSL versions a server supports
func (s *Scanner) detectProtocols(addr, network string, starttlsDialer func(string, time.Duration) (net.Conn, error)) []models.ProtocolVersion {
	var protocols []models.ProtocolVersion

	// Check SSLv2 and SSLv3 via raw socket
	for _, legacy := range []struct {
		name    string
		major   byte
		minor   byte
	}{
		{"SSLv2", 0x00, 0x02},
		{"SSLv3", 0x03, 0x00},
	} {
		supported := s.checkLegacyProtocol(addr, network, legacy.major, legacy.minor, starttlsDialer)
		protocols = append(protocols, models.ProtocolVersion{
			Name:      legacy.name,
			Supported: supported,
			Security:  models.SecurityInsecure,
		})
	}

	// Check TLS 1.0 through TLS 1.3
	for _, v := range tlsVersions {
		supported := s.checkTLSVersion(addr, network, v.Version, starttlsDialer)
		protocols = append(protocols, models.ProtocolVersion{
			Name:      v.Name,
			Supported: supported,
			Security:  v.Security,
		})
	}

	return protocols
}

// checkTLSVersion attempts a TLS connection with a specific version
func (s *Scanner) checkTLSVersion(addr, network string, version uint16, starttlsDialer func(string, time.Duration) (net.Conn, error)) bool {
	host, _, _ := net.SplitHostPort(addr)
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
		ServerName:         host,
	}

	conn, err := s.dialTLS(addr, network, cfg, starttlsDialer)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// checkLegacyProtocol sends a raw SSL ClientHello to detect SSLv2/SSLv3 support
func (s *Scanner) checkLegacyProtocol(addr, network string, major, minor byte, starttlsDialer func(string, time.Duration) (net.Conn, error)) bool {
	var conn net.Conn
	var err error

	if starttlsDialer != nil {
		conn, err = starttlsDialer(addr, s.Timeout)
	} else {
		conn, err = net.DialTimeout(network, addr, s.Timeout)
	}
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(s.Timeout))

	if major == 0x00 && minor == 0x02 {
		// SSLv2 ClientHello format
		return s.checkSSLv2(conn)
	}

	// SSLv3 / early TLS: send a minimal ClientHello
	clientHello := buildClientHello(major, minor)
	_, err = conn.Write(clientHello)
	if err != nil {
		return false
	}

	// Read response - look for ServerHello
	buf := make([]byte, 5)
	_, err = conn.Read(buf)
	if err != nil {
		return false
	}

	// Record type 22 = Handshake
	if buf[0] == 22 {
		return true
	}

	return false
}

// checkSSLv2 sends an SSLv2-style ClientHello
func (s *Scanner) checkSSLv2(conn net.Conn) bool {
	// SSLv2 ClientHello
	cipherSpecs := []byte{
		0x07, 0x00, 0xc0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
		0x05, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
		0x03, 0x00, 0x80, // SSL_CK_RC2_128_CBC_WITH_MD5
	}

	challenge := make([]byte, 16)
	for i := range challenge {
		challenge[i] = byte(i)
	}

	msgLen := 9 + len(cipherSpecs) + len(challenge)
	msg := make([]byte, 0, 2+msgLen)

	// 2-byte header with MSB set
	msg = append(msg, byte(0x80|((msgLen>>8)&0x7f)), byte(msgLen&0xff))
	msg = append(msg, 0x01) // MSG-CLIENT-HELLO
	msg = append(msg, 0x00, 0x02) // Version: SSL 2.0

	// Cipher specs length
	csLen := uint16(len(cipherSpecs))
	msg = append(msg, byte(csLen>>8), byte(csLen&0xff))

	// Session ID length = 0
	msg = append(msg, 0x00, 0x00)

	// Challenge length
	chLen := uint16(len(challenge))
	msg = append(msg, byte(chLen>>8), byte(chLen&0xff))

	msg = append(msg, cipherSpecs...)
	msg = append(msg, challenge...)

	_, err := conn.Write(msg)
	if err != nil {
		return false
	}

	// Read response
	resp := make([]byte, 3)
	_, err = conn.Read(resp)
	if err != nil {
		return false
	}

	// Check for SSLv2 ServerHello (msg type 4)
	if resp[2] == 0x04 {
		return true
	}

	return false
}

// buildClientHello creates a minimal TLS ClientHello message
func buildClientHello(major, minor byte) []byte {
	// Minimal cipher suites
	ciphers := []uint16{
		0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
		0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	}

	// Build ClientHello body
	var hello []byte

	// Client version
	hello = append(hello, major, minor)

	// Random (32 bytes)
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	hello = append(hello, random...)

	// Session ID (empty)
	hello = append(hello, 0x00)

	// Cipher suites
	csBytes := make([]byte, 2+len(ciphers)*2)
	binary.BigEndian.PutUint16(csBytes, uint16(len(ciphers)*2))
	for i, cs := range ciphers {
		binary.BigEndian.PutUint16(csBytes[2+i*2:], cs)
	}
	hello = append(hello, csBytes...)

	// Compression methods (null only)
	hello = append(hello, 0x01, 0x00)

	// Wrap in Handshake (type 1 = ClientHello)
	handshake := []byte{0x01}
	hLen := len(hello)
	handshake = append(handshake, byte(hLen>>16), byte(hLen>>8), byte(hLen))
	handshake = append(handshake, hello...)

	// Wrap in TLS record
	record := []byte{0x16, major, minor} // ContentType: Handshake
	rLen := len(handshake)
	record = append(record, byte(rLen>>8), byte(rLen))
	record = append(record, handshake...)

	return record
}

// GetProtocolSecurity returns the security level for a protocol name
func GetProtocolSecurity(name string) models.SecurityLevel {
	switch name {
	case "SSLv2", "SSLv3":
		return models.SecurityInsecure
	case "TLS 1.0", "TLS 1.1":
		return models.SecurityWeak
	case "TLS 1.2":
		return models.SecurityAcceptable
	case "TLS 1.3":
		return models.SecurityStrong
	default:
		return models.SecurityWeak
	}
}

// Ensure binary import is used
func init() {
	_ = fmt.Sprint
}
