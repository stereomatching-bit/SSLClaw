package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"sslclaw/internal/models"
)

// GenerateCSR generates a Certificate Signing Request
func GenerateCSR(opts models.CSROptions) (*models.CSRResult, error) {
	// Generate private key
	var privateKey crypto.PrivateKey
	var err error

	switch opts.KeyAlgorithm {
	case "RSA":
		keySize := opts.KeySize
		if keySize == 0 {
			keySize = 2048
		}
		privateKey, err = rsa.GenerateKey(rand.Reader, keySize)
	case "EC", "ECDSA":
		var curve elliptic.Curve
		switch opts.KeySize {
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", opts.KeyAlgorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("key generation failed: %v", err)
	}

	// Build CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         opts.CommonName,
			Organization:       filter(opts.Org),
			OrganizationalUnit: filter(opts.OrgUnit),
			Locality:           filter(opts.Locality),
			Province:           filter(opts.State),
			Country:            filter(opts.Country),
		},
	}

	if opts.Email != "" {
		template.EmailAddresses = []string{opts.Email}
	}

	if len(opts.SANs) > 0 {
		template.DNSNames = opts.SANs
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("CSR creation failed: %v", err)
	}

	// Encode CSR to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Encode private key to PEM
	keyPEM, err := ExportPrivateKeyPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("key export failed: %v", err)
	}

	return &models.CSRResult{
		CSR:        csrPEM,
		PrivateKey: keyPEM,
	}, nil
}

// ParseCSR parses a PEM-encoded CSR
func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
