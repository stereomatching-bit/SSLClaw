package models

import (
	"crypto/x509"
	"time"
)

// SecurityLevel indicates the security rating of a cipher or protocol
type SecurityLevel int

const (
	SecurityInsecure SecurityLevel = iota
	SecurityWeak
	SecurityAcceptable
	SecurityStrong
)

func (s SecurityLevel) String() string {
	switch s {
	case SecurityInsecure:
		return "Insecure"
	case SecurityWeak:
		return "Weak"
	case SecurityAcceptable:
		return "Acceptable"
	case SecurityStrong:
		return "Strong"
	default:
		return "Unknown"
	}
}

// ProtocolVersion represents a TLS/SSL protocol version
type ProtocolVersion struct {
	Name      string        `xml:"name,attr"`
	Supported bool          `xml:"supported,attr"`
	Security  SecurityLevel `xml:"security,attr"`
}

// CipherSuiteResult contains info about a particular cipher suite
type CipherSuiteResult struct {
	ID            uint16        `xml:"id,attr"`
	Name          string        `xml:"name"`
	Protocol      string        `xml:"protocol"`
	KeyExchange   string        `xml:"keyExchange"`
	Authentication string       `xml:"authentication"`
	Encryption    string        `xml:"encryption"`
	MAC           string        `xml:"mac"`
	Security      SecurityLevel `xml:"security"`
	IsPreferred   bool          `xml:"preferred,attr"`
}

// CertificateInfo holds parsed certificate details
type CertificateInfo struct {
	Subject            string    `xml:"subject"`
	Issuer             string    `xml:"issuer"`
	SerialNumber       string    `xml:"serialNumber"`
	NotBefore          time.Time `xml:"notBefore"`
	NotAfter           time.Time `xml:"notAfter"`
	SignatureAlgorithm string    `xml:"signatureAlgorithm"`
	PublicKeyAlgorithm string    `xml:"publicKeyAlgorithm"`
	PublicKeyBits      int       `xml:"publicKeyBits"`
	SANs               []string  `xml:"sans>san"`
	Fingerprints       map[string]string `xml:"-"`
	IsExpired          bool      `xml:"isExpired"`
	IsSelfSigned       bool      `xml:"isSelfSigned"`
	IsWeakSignature    bool      `xml:"isWeakSignature"`
	Raw                *x509.Certificate `xml:"-"`
}

// Vulnerability represents a detected security weakness
type Vulnerability struct {
	Name        string        `xml:"name"`
	Description string        `xml:"description"`
	Severity    SecurityLevel `xml:"severity"`
	Affected    string        `xml:"affected"`
}

// STARTTLSProtocol represents a STARTTLS-capable protocol
type STARTTLSProtocol string

const (
	STARTTLS_SMTP STARTTLSProtocol = "smtp"
	STARTTLS_IMAP STARTTLSProtocol = "imap"
	STARTTLS_POP3 STARTTLSProtocol = "pop3"
	STARTTLS_FTP  STARTTLSProtocol = "ftp"
	STARTTLS_XMPP STARTTLSProtocol = "xmpp"
	STARTTLS_NONE STARTTLSProtocol = "none"
)

// ScanOptions configures what to scan
type ScanOptions struct {
	Host             string           `xml:"host"`
	Port             int              `xml:"port"`
	TimeoutSeconds   int              `xml:"timeout"`
	STARTTLSProtocol STARTTLSProtocol `xml:"starttls"`
	CheckVulns       bool             `xml:"checkVulns"`
	IPv6             bool             `xml:"ipv6"`
}

// ScanResult holds the complete results of a scan
type ScanResult struct {
	Host            string              `xml:"host,attr"`
	Port            int                 `xml:"port,attr"`
	IP              string              `xml:"ip"`
	ScanTime        time.Time           `xml:"scanTime"`
	Duration        time.Duration       `xml:"-"`
	DurationStr     string              `xml:"duration"`
	Protocols       []ProtocolVersion   `xml:"protocols>protocol"`
	CipherSuites    []CipherSuiteResult `xml:"cipherSuites>cipher"`
	Certificates    []CertificateInfo   `xml:"certificates>certificate"`
	Vulnerabilities []Vulnerability     `xml:"vulnerabilities>vulnerability"`
	Error           string              `xml:"error,omitempty"`
}

// BatchScanResult holds results for multiple hosts
type BatchScanResult struct {
	Results   []ScanResult `xml:"results>result"`
	StartTime time.Time    `xml:"startTime"`
	EndTime   time.Time    `xml:"endTime"`
	Total     int          `xml:"total"`
	Succeeded int          `xml:"succeeded"`
	Failed    int          `xml:"failed"`
}
