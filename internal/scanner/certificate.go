package scanner

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sslclaw/internal/models"
	"time"
)

// inspectCertificates retrieves and parses server certificates
func (s *Scanner) inspectCertificates(addr, network string, starttlsDialer func(string, time.Duration) (net.Conn, error)) []models.CertificateInfo {
	host, _, _ := net.SplitHostPort(addr)
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	conn, err := s.dialTLS(addr, network, cfg, starttlsDialer)
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var certs []models.CertificateInfo

	for _, cert := range state.PeerCertificates {
		info := parseCertificate(cert)
		certs = append(certs, info)
	}

	return certs
}

// parseCertificate extracts relevant information from an x509 certificate
func parseCertificate(cert *x509.Certificate) models.CertificateInfo {
	info := models.CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SANs:               cert.DNSNames,
		Raw:                cert,
		Fingerprints:       make(map[string]string),
	}

	// Public key size
	info.PublicKeyBits = getPublicKeyBits(cert)

	// Fingerprints
	sha1Sum := sha1.Sum(cert.Raw)
	sha256Sum := sha256.Sum256(cert.Raw)
	info.Fingerprints["SHA-1"] = fmt.Sprintf("%X", sha1Sum)
	info.Fingerprints["SHA-256"] = fmt.Sprintf("%X", sha256Sum)

	// Check if expired
	now := time.Now()
	if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
		info.IsExpired = true
	}

	// Check if self-signed
	if cert.Issuer.String() == cert.Subject.String() {
		info.IsSelfSigned = true
	}

	// Check for weak signature algorithms
	info.IsWeakSignature = isWeakSignature(cert.SignatureAlgorithm)

	// Add IP SANs
	for _, ip := range cert.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}

	// Add email SANs
	info.SANs = append(info.SANs, cert.EmailAddresses...)

	return info
}

// getPublicKeyBits returns the key size in bits
func getPublicKeyBits(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		return pub.Size() * 8
	default:
		// Estimate from the raw public key
		return len(cert.RawSubjectPublicKeyInfo) * 8
	}
}

// isWeakSignature checks if a signature algorithm is considered weak
func isWeakSignature(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA,
		x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

// ValidateCertificateChain validates the certificate chain
func ValidateCertificateChain(certs []*x509.Certificate) models.ChainValidationResult {
	result := models.ChainValidationResult{}

	if len(certs) == 0 {
		result.Errors = append(result.Errors, "No certificates provided")
		return result
	}

	result.Chain = certs

	// Build intermediate pool
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	// Verify the leaf certificate
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())

		// Check for missing intermediate
		if len(certs) == 1 && !certs[0].IsCA {
			result.MissingIntermediate = true
			result.Errors = append(result.Errors, "Possible missing intermediate certificate")
		}
	} else {
		result.Valid = true
		if len(chains) > 0 {
			result.Chain = chains[0]
		}
	}

	return result
}
