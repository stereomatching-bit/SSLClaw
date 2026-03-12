package keystore

import (
	"crypto/x509"
	"fmt"
	"os"
	"sslclaw/internal/models"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// openPKCS12 reads a PKCS#12 keystore file
func openPKCS12(path, password string) (*models.KeyStoreInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read PKCS#12 file: %v", err)
	}

	privateKey, cert, caCerts, err := gopkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS#12: %v", err)
	}

	info := &models.KeyStoreInfo{
		Path:    path,
		Type:    models.KeyStorePKCS12,
		Entries: []models.KeyStoreEntry{},
	}

	// Add the main private key entry
	if cert != nil {
		certInfo := parseCertForKeystore(cert)
		entry := models.KeyStoreEntry{
			Alias:         cert.Subject.CommonName,
			Type:          models.EntryPrivateKey,
			HasPrivateKey: privateKey != nil,
			Certificate:   &certInfo,
			KeyAlgorithm:  cert.PublicKeyAlgorithm.String(),
			KeySize:       getKeyBits(cert),
			CreationDate:  cert.NotBefore,
		}

		// Build cert chain
		entry.CertChain = append(entry.CertChain, &certInfo)
		for _, ca := range caCerts {
			caInfo := parseCertForKeystore(ca)
			entry.CertChain = append(entry.CertChain, &caInfo)
		}

		info.Entries = append(info.Entries, entry)
	}

	// Add CA certs as trusted certificate entries
	for _, ca := range caCerts {
		caInfo := parseCertForKeystore(ca)
		entry := models.KeyStoreEntry{
			Alias:        ca.Subject.CommonName,
			Type:         models.EntryTrustedCert,
			Certificate:  &caInfo,
			KeyAlgorithm: ca.PublicKeyAlgorithm.String(),
			KeySize:      getKeyBits(ca),
			CreationDate: ca.NotBefore,
		}
		info.Entries = append(info.Entries, entry)
	}

	return info, nil
}

// savePKCS12 writes entries to a PKCS#12 file
func savePKCS12(info *models.KeyStoreInfo, path, password string) error {
	// Find the private key entry
	var privateKey interface{}
	var cert *x509.Certificate
	var caCerts []*x509.Certificate

	for _, entry := range info.Entries {
		if entry.Type == models.EntryPrivateKey && entry.Certificate != nil {
			cert = entry.Certificate.Raw
			// Extract CA certs from chain
			if len(entry.CertChain) > 1 {
				for _, chainCert := range entry.CertChain[1:] {
					if chainCert.Raw != nil {
						caCerts = append(caCerts, chainCert.Raw)
					}
				}
			}
			break
		}
	}

	if cert == nil {
		return fmt.Errorf("no certificate found for PKCS#12 export")
	}

	data, err := gopkcs12.Modern.Encode(privateKey, cert, caCerts, password)
	if err != nil {
		return fmt.Errorf("failed to encode PKCS#12: %v", err)
	}

	err = os.WriteFile(path, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write PKCS#12 file: %v", err)
	}

	info.Path = path
	info.Modified = false
	return nil
}
