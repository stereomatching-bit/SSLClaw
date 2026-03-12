package keystore

import (
	"crypto/x509"
	"sslclaw/internal/models"
)

// ValidateChain validates the certificate chain of an entry
func ValidateChain(entry models.KeyStoreEntry) models.ChainValidationResult {
	result := models.ChainValidationResult{}

	if entry.Certificate == nil || entry.Certificate.Raw == nil {
		result.Errors = append(result.Errors, "No certificate to validate")
		return result
	}

	// Collect all certificates
	var certs []*x509.Certificate
	certs = append(certs, entry.Certificate.Raw)

	for _, chainCert := range entry.CertChain {
		if chainCert.Raw != nil && chainCert.Raw != entry.Certificate.Raw {
			certs = append(certs, chainCert.Raw)
		}
	}

	result.Chain = certs

	// Build intermediate pool
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	// Verify
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())

		// Check for possible missing intermediate
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

// ValidateChainFromCerts validates a raw certificate chain
func ValidateChainFromCerts(certs []*x509.Certificate) models.ChainValidationResult {
	result := models.ChainValidationResult{}

	if len(certs) == 0 {
		result.Errors = append(result.Errors, "No certificates provided")
		return result
	}

	result.Chain = certs

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Intermediates: intermediates,
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())
		if len(certs) == 1 && !certs[0].IsCA {
			result.MissingIntermediate = true
		}
	} else {
		result.Valid = true
		if len(chains) > 0 {
			result.Chain = chains[0]
		}
	}

	return result
}
