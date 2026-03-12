package keystore

import (
	"fmt"
	"sslclaw/internal/models"
)

// Convert converts between keystore formats
func Convert(opts models.ConvertOptions) error {
	// Open source keystore
	var sourceInfo *models.KeyStoreInfo
	var err error

	switch opts.SourceType {
	case models.KeyStoreJKS:
		sourceInfo, err = openJKS(opts.SourcePath, opts.SourcePassword)
	case models.KeyStorePKCS12:
		sourceInfo, err = openPKCS12(opts.SourcePath, opts.SourcePassword)
	default:
		return fmt.Errorf("unsupported source type: %s", opts.SourceType)
	}

	if err != nil {
		return fmt.Errorf("failed to open source keystore: %v", err)
	}

	// Save as destination format
	switch opts.DestType {
	case models.KeyStoreJKS:
		return saveJKS(sourceInfo, opts.DestPath, opts.DestPassword)
	case models.KeyStorePKCS12:
		return savePKCS12(sourceInfo, opts.DestPath, opts.DestPassword)
	default:
		return fmt.Errorf("unsupported destination type: %s", opts.DestType)
	}
}
