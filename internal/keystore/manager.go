package keystore

import (
	"fmt"
	"sslclaw/internal/models"
)

// Manager provides operations for keystore management
type Manager struct {
	currentStore *models.KeyStoreInfo
}

// NewManager creates a new keystore manager
func NewManager() *Manager {
	return &Manager{}
}

// Open opens a keystore file
func (m *Manager) Open(path, password string, storeType models.KeyStoreType) (*models.KeyStoreInfo, error) {
	var info *models.KeyStoreInfo
	var err error

	switch storeType {
	case models.KeyStoreJKS:
		info, err = openJKS(path, password)
		if err != nil {
			// Fallback: Try opening as PKCS12
			infoPKCS, errPKCS := openPKCS12(path, password)
			if errPKCS == nil {
				info = infoPKCS
				err = nil
			}
		}
	case models.KeyStorePKCS12:
		info, err = openPKCS12(path, password)
		if err != nil {
			// Fallback: Try opening as JKS
			infoJKS, errJKS := openJKS(path, password)
			if errJKS == nil {
				info = infoJKS
				err = nil
			}
		}
	default:
		return nil, fmt.Errorf("unsupported keystore type: %s", storeType)
	}

	if err != nil {
		return nil, err
	}

	m.currentStore = info
	return info, nil
}

// Save saves the current keystore to file
func (m *Manager) Save(path, password string, storeType models.KeyStoreType) error {
	if m.currentStore == nil {
		return fmt.Errorf("no keystore is currently open")
	}

	switch storeType {
	case models.KeyStoreJKS:
		return saveJKS(m.currentStore, path, password)
	case models.KeyStorePKCS12:
		return savePKCS12(m.currentStore, path, password)
	default:
		return fmt.Errorf("unsupported keystore type: %s", storeType)
	}
}

// CreateNew creates a new empty keystore
func (m *Manager) CreateNew(storeType models.KeyStoreType) *models.KeyStoreInfo {
	info := &models.KeyStoreInfo{
		Type:    storeType,
		Entries: []models.KeyStoreEntry{},
	}
	m.currentStore = info
	return info
}

// GetCurrentStore returns the currently open keystore
func (m *Manager) GetCurrentStore() *models.KeyStoreInfo {
	return m.currentStore
}

// AddEntry adds an entry to the current keystore
func (m *Manager) AddEntry(entry models.KeyStoreEntry) error {
	if m.currentStore == nil {
		return fmt.Errorf("no keystore is currently open")
	}

	// Check for duplicate alias
	for _, e := range m.currentStore.Entries {
		if e.Alias == entry.Alias {
			return fmt.Errorf("alias '%s' already exists in keystore", entry.Alias)
		}
	}

	m.currentStore.Entries = append(m.currentStore.Entries, entry)
	m.currentStore.Modified = true
	return nil
}

// DeleteEntry removes an entry by alias
func (m *Manager) DeleteEntry(alias string) error {
	if m.currentStore == nil {
		return fmt.Errorf("no keystore is currently open")
	}

	for i, e := range m.currentStore.Entries {
		if e.Alias == alias {
			m.currentStore.Entries = append(m.currentStore.Entries[:i], m.currentStore.Entries[i+1:]...)
			m.currentStore.Modified = true
			return nil
		}
	}
	return fmt.Errorf("alias '%s' not found", alias)
}

// RenameEntry changes an entry's alias
func (m *Manager) RenameEntry(oldAlias, newAlias string) error {
	if m.currentStore == nil {
		return fmt.Errorf("no keystore is currently open")
	}

	// Check new alias doesn't exist
	for _, e := range m.currentStore.Entries {
		if e.Alias == newAlias {
			return fmt.Errorf("alias '%s' already exists", newAlias)
		}
	}

	for i, e := range m.currentStore.Entries {
		if e.Alias == oldAlias {
			m.currentStore.Entries[i].Alias = newAlias
			m.currentStore.Modified = true
			return nil
		}
	}
	return fmt.Errorf("alias '%s' not found", oldAlias)
}

// GetEntry returns an entry by alias
func (m *Manager) GetEntry(alias string) (*models.KeyStoreEntry, error) {
	if m.currentStore == nil {
		return nil, fmt.Errorf("no keystore is currently open")
	}

	for _, e := range m.currentStore.Entries {
		if e.Alias == alias {
			return &e, nil
		}
	}
	return nil, fmt.Errorf("alias '%s' not found", alias)
}

// DetectType detects the keystore type from file extension
func DetectType(path string) models.KeyStoreType {
	switch {
	case hasExtension(path, ".jks"), hasExtension(path, ".key"), hasExtension(path, ".truststore"):
		return models.KeyStoreJKS
	case hasExtension(path, ".p12"), hasExtension(path, ".pfx"):
		return models.KeyStorePKCS12
	default:
		return models.KeyStorePKCS12 // default to PKCS12
	}
}

func hasExtension(path, ext string) bool {
	if len(path) < len(ext) {
		return false
	}
	suffix := path[len(path)-len(ext):]
	return suffix == ext || suffix == upperString(ext)
}

func upperString(s string) string {
	result := make([]byte, len(s))
	for i, c := range []byte(s) {
		if c >= 'a' && c <= 'z' {
			result[i] = c - 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}
