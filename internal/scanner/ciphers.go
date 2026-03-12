package scanner

import (
	"crypto/tls"
	"net"
	"sslclaw/internal/models"
	"strings"
	"time"
)

// Known cipher suite security classifications
var cipherSecurity = map[uint16]models.SecurityLevel{
	// Insecure ciphers
	tls.TLS_RSA_WITH_RC4_128_SHA:                models.SecurityInsecure,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           models.SecurityWeak,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          models.SecurityInsecure,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        models.SecurityInsecure,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     models.SecurityWeak,

	// Acceptable ciphers
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:             models.SecurityAcceptable,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:             models.SecurityAcceptable,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:          models.SecurityAcceptable,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:          models.SecurityAcceptable,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:          models.SecurityAcceptable,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:       models.SecurityAcceptable,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:     models.SecurityAcceptable,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:       models.SecurityAcceptable,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:     models.SecurityAcceptable,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:    models.SecurityAcceptable,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:  models.SecurityAcceptable,

	// Strong ciphers
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:    models.SecurityStrong,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:  models.SecurityStrong,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:    models.SecurityStrong,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:  models.SecurityStrong,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   models.SecurityStrong,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: models.SecurityStrong,

	// TLS 1.3 ciphers (always strong)
	tls.TLS_AES_128_GCM_SHA256:       models.SecurityStrong,
	tls.TLS_AES_256_GCM_SHA384:       models.SecurityStrong,
	tls.TLS_CHACHA20_POLY1305_SHA256: models.SecurityStrong,
}

// enumerateCiphers tests which cipher suites are supported
func (s *Scanner) enumerateCiphers(addr, network string, starttlsDialer func(string, time.Duration) (net.Conn, error)) []models.CipherSuiteResult {
	var results []models.CipherSuiteResult
	host, _, _ := net.SplitHostPort(addr)

	// Get server's preferred cipher by connecting with all ciphers
	preferredCiphers := make(map[uint16]bool)

	// Test TLS 1.2 and below ciphers
	allCiphers := tls.CipherSuites()
	insecureCiphers := tls.InsecureCipherSuites()
	allList := append(allCiphers, insecureCiphers...)

	for _, cs := range allList {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10} {
			// Check if this cipher supports this version
			supported := false
			for _, sv := range cs.SupportedVersions {
				if sv == version {
					supported = true
					break
				}
			}
			if !supported {
				continue
			}

			cfg := &tls.Config{
				InsecureSkipVerify: true,
				CipherSuites:      []uint16{cs.ID},
				MinVersion:        version,
				MaxVersion:        version,
				ServerName:        host,
			}

			conn, err := s.dialTLS(addr, network, cfg, starttlsDialer)
			if err != nil {
				continue
			}

			state := conn.ConnectionState()
			conn.Close()

			security := getCipherSecurity(cs.ID, cs.Name)
			versionName := tlsVersionName(version)

			result := models.CipherSuiteResult{
				ID:       cs.ID,
				Name:     cs.Name,
				Protocol: versionName,
				Security: security,
			}

			// Parse cipher name for details
			parseCipherDetails(&result)

			// Check if this is the server's preferred cipher
			if _, exists := preferredCiphers[version]; !exists {
				preferredCiphers[version] = true
				if state.CipherSuite == cs.ID {
					result.IsPreferred = true
				}
			}

			results = append(results, result)
		}
	}

	// TLS 1.3 ciphers are automatically negotiated
	cfg13 := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:        tls.VersionTLS13,
		MaxVersion:        tls.VersionTLS13,
		ServerName:        host,
	}
	conn13, err := s.dialTLS(addr, network, cfg13, starttlsDialer)
	if err == nil {
		state := conn13.ConnectionState()
		conn13.Close()

		tls13Ciphers := []struct {
			id   uint16
			name string
		}{
			{tls.TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"},
			{tls.TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"},
			{tls.TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"},
		}

		for _, cs := range tls13Ciphers {
			result := models.CipherSuiteResult{
				ID:       cs.id,
				Name:     cs.name,
				Protocol: "TLS 1.3",
				Security: models.SecurityStrong,
			}
			parseCipherDetails(&result)

			if state.CipherSuite == cs.id {
				result.IsPreferred = true
			}
			results = append(results, result)
		}
	}

	return results
}

// getCipherSecurity returns the security level for a cipher suite
func getCipherSecurity(id uint16, name string) models.SecurityLevel {
	if level, ok := cipherSecurity[id]; ok {
		return level
	}

	// Heuristic based on name
	nameLower := strings.ToLower(name)
	if strings.Contains(nameLower, "rc4") || strings.Contains(nameLower, "null") ||
		strings.Contains(nameLower, "export") || strings.Contains(nameLower, "des40") ||
		strings.Contains(nameLower, "rc2") {
		return models.SecurityInsecure
	}
	if strings.Contains(nameLower, "3des") || strings.Contains(nameLower, "des_cbc") {
		return models.SecurityWeak
	}
	if strings.Contains(nameLower, "gcm") || strings.Contains(nameLower, "chacha20") {
		return models.SecurityStrong
	}
	return models.SecurityAcceptable
}

// parseCipherDetails extracts key exchange, auth, encryption, MAC from cipher name
func parseCipherDetails(cs *models.CipherSuiteResult) {
	name := cs.Name

	// Key exchange
	if strings.Contains(name, "ECDHE") {
		cs.KeyExchange = "ECDHE"
	} else if strings.Contains(name, "DHE") {
		cs.KeyExchange = "DHE"
	} else if strings.Contains(name, "RSA") {
		cs.KeyExchange = "RSA"
	}

	// Authentication
	if strings.Contains(name, "ECDSA") {
		cs.Authentication = "ECDSA"
	} else if strings.Contains(name, "RSA") {
		cs.Authentication = "RSA"
	}

	// Encryption
	if strings.Contains(name, "CHACHA20") {
		cs.Encryption = "ChaCha20-Poly1305"
	} else if strings.Contains(name, "AES_256_GCM") {
		cs.Encryption = "AES-256-GCM"
	} else if strings.Contains(name, "AES_128_GCM") {
		cs.Encryption = "AES-128-GCM"
	} else if strings.Contains(name, "AES_256_CBC") {
		cs.Encryption = "AES-256-CBC"
	} else if strings.Contains(name, "AES_128_CBC") {
		cs.Encryption = "AES-128-CBC"
	} else if strings.Contains(name, "3DES") {
		cs.Encryption = "3DES"
	} else if strings.Contains(name, "RC4") {
		cs.Encryption = "RC4"
	}

	// MAC
	if strings.Contains(name, "SHA384") {
		cs.MAC = "SHA-384"
	} else if strings.Contains(name, "SHA256") {
		cs.MAC = "SHA-256"
	} else if strings.Contains(name, "SHA") {
		cs.MAC = "SHA-1"
	}
}

// tlsVersionName returns a human-readable name for a TLS version
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
