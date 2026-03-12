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
	"math/big"
	"sslclaw/internal/models"
	"time"
)

// GenerateKeyPair generates a key pair and self-signed certificate
func GenerateKeyPair(opts models.KeyPairOptions) (crypto.PrivateKey, *x509.Certificate, []byte, error) {
	var privateKey crypto.PrivateKey
	var err error

	switch opts.Algorithm {
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
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %s", opts.Algorithm)
	}

	if err != nil {
		return nil, nil, nil, fmt.Errorf("key generation failed: %v", err)
	}

	// Generate self-signed certificate
	validDays := opts.ValidDays
	if validDays <= 0 {
		validDays = 365
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         opts.CommonName,
			Organization:       filter(opts.Org),
			OrganizationalUnit: filter(opts.OrgUnit),
			Locality:           filter(opts.Locality),
			Province:           filter(opts.State),
			Country:            filter(opts.Country),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Get public key
	var publicKey crypto.PublicKey
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &k.PublicKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certificate creation failed: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("certificate parsing failed: %v", err)
	}

	return privateKey, cert, certDER, nil
}

// ExportPrivateKeyPEM exports a private key in PEM format
func ExportPrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	var derBytes []byte
	var pemType string
	var err error

	switch k := key.(type) {
	case *rsa.PrivateKey:
		derBytes = x509.MarshalPKCS1PrivateKey(k)
		pemType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		derBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		pemType = "EC PRIVATE KEY"
	default:
		return nil, fmt.Errorf("unsupported key type")
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: derBytes,
	}), nil
}

// ExportCertificatePEM exports a certificate in PEM format
func ExportCertificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// ExportCertificateDER exports a certificate in DER format
func ExportCertificateDER(cert *x509.Certificate) []byte {
	return cert.Raw
}

// ImportCertificatePEM imports a certificate from PEM data
func ImportCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ImportCertificateDER imports a certificate from DER data
func ImportCertificateDER(data []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(data)
}

func filter(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
