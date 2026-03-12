package models

import (
	"crypto/x509"
	"time"
)

// KeyStoreType represents the type of keystore
type KeyStoreType string

const (
	KeyStoreJKS    KeyStoreType = "JKS"
	KeyStorePKCS12 KeyStoreType = "PKCS12"
)

// EntryType represents the type of keystore entry
type EntryType string

const (
	EntryPrivateKey   EntryType = "PrivateKey"
	EntryTrustedCert  EntryType = "TrustedCertificate"
	EntrySecretKey    EntryType = "SecretKey"
)

// KeyStoreEntry represents a single entry in a keystore
type KeyStoreEntry struct {
	Alias         string
	Type          EntryType
	CreationDate  time.Time
	Certificate   *CertificateInfo
	CertChain     []*CertificateInfo
	HasPrivateKey bool
	KeyAlgorithm  string
	KeySize       int
}

// KeyStoreInfo represents an opened keystore
type KeyStoreInfo struct {
	Path     string
	Type     KeyStoreType
	Entries  []KeyStoreEntry
	Modified bool
}

// KeyPairOptions configures key pair generation
type KeyPairOptions struct {
	Algorithm   string // RSA, DSA, EC
	KeySize     int    // 2048, 4096 for RSA; 256, 384, 521 for EC
	CommonName  string
	Org         string
	OrgUnit     string
	Locality    string
	State       string
	Country     string
	ValidDays   int
	Alias       string
}

// CSROptions configures CSR generation
type CSROptions struct {
	CommonName   string
	Org          string
	OrgUnit      string
	Locality     string
	State        string
	Country      string
	Email        string
	SANs         []string
	KeyAlgorithm string
	KeySize      int
}

// CSRResult holds a generated CSR and its key
type CSRResult struct {
	CSR        []byte // PEM-encoded CSR
	PrivateKey []byte // PEM-encoded private key
}

// ConvertOptions configures keystore conversion
type ConvertOptions struct {
	SourcePath     string
	SourceType     KeyStoreType
	SourcePassword string
	DestPath       string
	DestType       KeyStoreType
	DestPassword   string
}

// ChainValidationResult holds certificate chain validation results
type ChainValidationResult struct {
	Valid              bool
	Chain              []*x509.Certificate
	MissingIntermediate bool
	Errors             []string
}
