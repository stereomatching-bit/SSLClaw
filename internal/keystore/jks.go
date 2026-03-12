package keystore

import (
	"crypto/x509"
	"fmt"
	"os"
	"sslclaw/internal/models"
	"time"

	ks "github.com/pavlo-v-chernykh/keystore-go/v4"
)

// openJKS reads a JKS keystore file
func openJKS(path, password string) (*models.KeyStoreInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open JKS file: %v", err)
	}
	defer f.Close()

	store := ks.New()
	err = store.Load(f, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("failed to load JKS keystore: %v", err)
	}

	info := &models.KeyStoreInfo{
		Path:    path,
		Type:    models.KeyStoreJKS,
		Entries: []models.KeyStoreEntry{},
	}

	for _, alias := range store.Aliases() {
		entry := models.KeyStoreEntry{
			Alias: alias,
		}

		if store.IsPrivateKeyEntry(alias) {
			entry.Type = models.EntryPrivateKey
			entry.HasPrivateKey = true

			pke, err := store.GetPrivateKeyEntry(alias, []byte(password))
			if err == nil {
				entry.CreationDate = pke.CreationTime

				// Parse certificate chain
				for _, certBytes := range pke.CertificateChain {
					cert, err := x509.ParseCertificate(certBytes.Content)
					if err == nil {
						certInfo := parseCertForKeystore(cert)
						entry.CertChain = append(entry.CertChain, &certInfo)
						if entry.Certificate == nil {
							entry.Certificate = &certInfo
							entry.KeyAlgorithm = cert.PublicKeyAlgorithm.String()
							entry.KeySize = getKeyBits(cert)
						}
					}
				}
			}
		} else if store.IsTrustedCertificateEntry(alias) {
			entry.Type = models.EntryTrustedCert
			tce, err := store.GetTrustedCertificateEntry(alias)
			if err == nil {
				entry.CreationDate = tce.CreationTime
				cert, err := x509.ParseCertificate(tce.Certificate.Content)
				if err == nil {
					certInfo := parseCertForKeystore(cert)
					entry.Certificate = &certInfo
					entry.KeyAlgorithm = cert.PublicKeyAlgorithm.String()
					entry.KeySize = getKeyBits(cert)
				}
			}
		}

		info.Entries = append(info.Entries, entry)
	}

	return info, nil
}

// saveJKS writes entries to a JKS keystore file
func saveJKS(info *models.KeyStoreInfo, path, password string) error {
	store := ks.New()

	for _, entry := range info.Entries {
		switch entry.Type {
		case models.EntryTrustedCert:
			if entry.Certificate != nil && entry.Certificate.Raw != nil {
				tce := ks.TrustedCertificateEntry{
					CreationTime: entry.CreationDate,
					Certificate: ks.Certificate{
						Type:    "X.509",
						Content: entry.Certificate.Raw.Raw,
					},
				}
				err := store.SetTrustedCertificateEntry(entry.Alias, tce)
				if err != nil {
					return fmt.Errorf("failed to set trusted cert entry '%s': %v", entry.Alias, err)
				}
			}
		case models.EntryPrivateKey:
			// For private key entries, we need the raw key data
			// This is handled during import operations
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create JKS file: %v", err)
	}
	defer f.Close()

	err = store.Store(f, []byte(password))
	if err != nil {
		return fmt.Errorf("failed to save JKS keystore: %v", err)
	}

	info.Path = path
	info.Modified = false
	return nil
}

// parseCertForKeystore creates a CertificateInfo from an x509.Certificate
func parseCertForKeystore(cert *x509.Certificate) models.CertificateInfo {
	info := models.CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:      getKeyBits(cert),
		SANs:               cert.DNSNames,
		Raw:                cert,
		Fingerprints:       make(map[string]string),
	}

	now := time.Now()
	info.IsExpired = now.After(cert.NotAfter) || now.Before(cert.NotBefore)
	info.IsSelfSigned = cert.Issuer.String() == cert.Subject.String()

	return info
}

func getKeyBits(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case interface{ Size() int }:
		return pub.Size() * 8
	default:
		_ = pub
		return 0
	}
}
