package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"sslclaw/internal/keystore"
	"sslclaw/internal/models"
)

// KeyStoreTab creates the KeyStore Manager tab content
func KeyStoreTab(win fyne.Window) fyne.CanvasObject {
	mgr := keystore.NewManager()

	// --- Entry list (Table-like) ---
	entryList := widget.NewList(
		func() int { return 0 },
		func() fyne.CanvasObject {
			grid := container.NewGridWithColumns(5,
				widget.NewLabel(""),
				widget.NewLabel(""),
				widget.NewLabel(""),
				widget.NewLabel(""),
				widget.NewLabel(""),
			)
			return newDoubleClickableGrid(grid, nil, nil)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {},
	)

	statusLabel := widget.NewLabel("No keystore loaded")
	statusLabel.TextStyle = fyne.TextStyle{Italic: true}

	// Double-click handler
	showDetailWindow := func(entry models.KeyStoreEntry) {
		detailWin := fyne.CurrentApp().NewWindow("Entry Details: " + entry.Alias)
		detailWin.Resize(fyne.NewSize(600, 500))
		
		text := widget.NewMultiLineEntry()
		text.SetText(formatEntryDetails(entry))
		text.Disable()
		
		closeBtn := widget.NewButton("Close", func() {
			detailWin.Close()
		})
		
		detailContent := container.NewBorder(nil, closeBtn, nil, nil, container.NewScroll(text))
		detailWin.SetContent(detailContent)
		detailWin.Show()
	}

	// Refresh entry list
	refreshList := func() {
		store := mgr.GetCurrentStore()
		if store == nil {
			entryList.Length = func() int { return 0 }
			entryList.Refresh()
			return
		}

		entries := store.Entries
		entryList.Length = func() int { return len(entries) }
		entryList.UpdateItem = func(id widget.ListItemID, obj fyne.CanvasObject) {
			dg := obj.(*doubleClickableGrid)
			grid := dg.grid
			aliasLabel := grid.Objects[0].(*widget.Label)
			typeLabel := grid.Objects[1].(*widget.Label)
			algoLabel := grid.Objects[2].(*widget.Label)
			sizeLabel := grid.Objects[3].(*widget.Label)
			dateLabel := grid.Objects[4].(*widget.Label)

			entry := entries[id]
			
			aliasLabel.SetText(entry.Alias)
			
			icon := "🔑 Key"
			if entry.Type == models.EntryTrustedCert {
				icon = "📜 Cert"
			} else if entry.Type == models.EntrySecretKey {
				icon = "🔐 Secret"
			}
			typeLabel.SetText(icon)
			
			algoLabel.SetText(entry.KeyAlgorithm)
			if entry.KeySize > 0 {
				sizeLabel.SetText(fmt.Sprintf("%d", entry.KeySize))
			} else {
				sizeLabel.SetText("-")
			}
			
			dateLabel.SetText(entry.CreationDate.Format("2006-01-02"))

			// Update click handlers
			dg.onTap = func() {
				entryList.Select(id)
			}
			dg.onDoubleTap = func() {
				showDetailWindow(entry)
			}
		}
		entryList.Refresh()
	}

	var selectedIndex int = -1

	// Show entry details
	entryList.OnSelected = func(id widget.ListItemID) {
		selectedIndex = id
	}

	entryList.OnUnselected = func(id widget.ListItemID) {
		if selectedIndex == id {
			selectedIndex = -1
		}
	}

	// --- Toolbar Buttons ---
	newBtn := widget.NewButton("New", func() {
		typeSelect := widget.NewSelect([]string{"JKS", "PKCS12"}, nil)
		typeSelect.SetSelected("PKCS12")

		dialog.ShowCustomConfirm("New KeyStore", "Create", "Cancel",
			container.NewVBox(
				widget.NewLabel("Select keystore type:"),
				typeSelect,
			), func(ok bool) {
				if !ok {
					return
				}
				var ksType models.KeyStoreType
				if typeSelect.Selected == "JKS" {
					ksType = models.KeyStoreJKS
				} else {
					ksType = models.KeyStorePKCS12
				}
				mgr.CreateNew(ksType)
				statusLabel.SetText(fmt.Sprintf("New %s keystore created", ksType))
				refreshList()
			}, win)
	})

	openBtn := widget.NewButton("Open", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			path := reader.URI().Path()
			reader.Close()

			passwordEntry := widget.NewPasswordEntry()
			var d dialog.Dialog
			onConfirm := func(ok bool) {
				if !ok {
					return
				}
				ksType := keystore.DetectType(path)
				info, err := mgr.Open(path, passwordEntry.Text, ksType)
				if err != nil {
					dialog.ShowError(err, win)
					return
				}
				statusLabel.SetText(fmt.Sprintf("Opened %s (%d entries)", path, len(info.Entries)))
				refreshList()
			}
			d = dialog.NewCustomConfirm("Enter Password", "OK", "Cancel",
				container.NewVBox(
					widget.NewLabel("KeyStore password:"),
					passwordEntry,
				), onConfirm, win)

			passwordEntry.OnSubmitted = func(s string) {
				d.Hide()
				onConfirm(true)
			}
			d.Show()
			win.Canvas().Focus(passwordEntry)
		}, win)
	})

	saveBtn := widget.NewButton("Save", func() {
		store := mgr.GetCurrentStore()
		if store == nil {
			dialog.ShowInformation("No KeyStore", "No keystore is currently open", win)
			return
		}

		passwordEntry := widget.NewPasswordEntry()
		var d dialog.Dialog
		onConfirm := func(ok bool) {
			if !ok {
				return
			}
			if store.Path == "" {
				// Save As
				dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
					if err != nil || writer == nil {
						return
					}
					path := writer.URI().Path()
					writer.Close()
					err = mgr.Save(path, passwordEntry.Text, store.Type)
					if err != nil {
						dialog.ShowError(err, win)
						return
					}
					statusLabel.SetText("Saved: " + path)
				}, win)
			} else {
				err := mgr.Save(store.Path, passwordEntry.Text, store.Type)
				if err != nil {
					dialog.ShowError(err, win)
					return
				}
				statusLabel.SetText("Saved: " + store.Path)
			}
		}
		d = dialog.NewCustomConfirm("Save KeyStore", "Save", "Cancel",
			container.NewVBox(
				widget.NewLabel("KeyStore password:"),
				passwordEntry,
			), onConfirm, win)

		passwordEntry.OnSubmitted = func(s string) {
			d.Hide()
			onConfirm(true)
		}
		d.Show()
		win.Canvas().Focus(passwordEntry)
	})

	// --- Certificate Operations ---
	importCertBtn := widget.NewButton("Import Cert", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			defer reader.Close()
			path := reader.URI().Path()
			data, err := os.ReadFile(path)
			if err != nil {
				dialog.ShowError(err, win)
				return
			}

			cert, err := keystore.ImportCertificatePEM(data)
			if err != nil {
				cert, err = keystore.ImportCertificateDER(data)
			}
			if err != nil {
				dialog.ShowError(fmt.Errorf("Failed to parse certificate: %v", err), win)
				return
			}

			aliasEntry := widget.NewEntry()
			aliasEntry.SetText(cert.Subject.CommonName)

			dialog.ShowCustomConfirm("Import Certificate", "Import", "Cancel",
				container.NewVBox(
					widget.NewLabel("Alias:"),
					aliasEntry,
				), func(ok bool) {
					if !ok {
						return
					}
					certInfo := models.CertificateInfo{
						Subject:            cert.Subject.String(),
						Issuer:             cert.Issuer.String(),
						SerialNumber:       cert.SerialNumber.String(),
						NotBefore:          cert.NotBefore,
						NotAfter:           cert.NotAfter,
						SignatureAlgorithm: cert.SignatureAlgorithm.String(),
						PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
						Raw:                cert,
					}
					entry := models.KeyStoreEntry{
						Alias:        aliasEntry.Text,
						Type:         models.EntryTrustedCert,
						Certificate:  &certInfo,
						CreationDate: time.Now(),
					}
					err := mgr.AddEntry(entry)
					if err != nil {
						dialog.ShowError(err, win)
						return
					}
					refreshList()
					statusLabel.SetText("Imported: " + aliasEntry.Text)
				}, win)
		}, win)
	})

	exportCertBtn := widget.NewButton("Export Cert", func() {
		store := mgr.GetCurrentStore()
		if store == nil {
			dialog.ShowInformation("No KeyStore", "Open a keystore first", win)
			return
		}
		idx := selectedIndex
		if idx < 0 || idx >= len(store.Entries) {
			dialog.ShowInformation("No Selection", "Select an entry to export", win)
			return
		}
		entry := store.Entries[idx]
		if entry.Certificate == nil || entry.Certificate.Raw == nil {
			dialog.ShowError(fmt.Errorf("No certificate in selected entry"), win)
			return
		}

		formatSelect := widget.NewSelect([]string{"PEM", "DER"}, nil)
		formatSelect.SetSelected("PEM")

		dialog.ShowCustomConfirm("Export Certificate", "Export", "Cancel",
			container.NewVBox(
				widget.NewLabel("Format:"),
				formatSelect,
			), func(ok bool) {
				if !ok {
					return
				}
				dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
					if err != nil || writer == nil {
						return
					}
					defer writer.Close()

					var data []byte
					if formatSelect.Selected == "PEM" {
						data = keystore.ExportCertificatePEM(entry.Certificate.Raw)
					} else {
						data = keystore.ExportCertificateDER(entry.Certificate.Raw)
					}
					writer.Write(data)
					statusLabel.SetText("Exported: " + entry.Alias)
				}, win)
			}, win)
	})

	// --- Key Generation ---
	genKeyBtn := widget.NewButton("Generate Key Pair", func() {
		showKeyGenDialog(win, mgr, refreshList, statusLabel)
	})

	// --- CSR Generation ---
	csrBtn := widget.NewButton("Generate CSR", func() {
		showCSRDialog(win, statusLabel)
	})

	// --- Delete & Rename ---
	deleteBtn := widget.NewButton("Delete", func() {
		store := mgr.GetCurrentStore()
		if store == nil {
			return
		}
		idx := selectedIndex
		if idx < 0 || idx >= len(store.Entries) {
			dialog.ShowInformation("No Selection", "Select an entry to delete", win)
			return
		}
		alias := store.Entries[idx].Alias
		dialog.ShowConfirm("Delete Entry", fmt.Sprintf("Delete '%s'?", alias), func(ok bool) {
			if ok {
				mgr.DeleteEntry(alias)
				refreshList()
				statusLabel.SetText("Deleted: " + alias)
			}
		}, win)
	})

	renameBtn := widget.NewButton("Rename", func() {
		store := mgr.GetCurrentStore()
		if store == nil {
			return
		}
		idx := selectedIndex
		if idx < 0 || idx >= len(store.Entries) {
			dialog.ShowInformation("No Selection", "Select an entry to rename", win)
			return
		}
		oldAlias := store.Entries[idx].Alias
		newAliasEntry := widget.NewEntry()
		newAliasEntry.SetText(oldAlias)

		dialog.ShowCustomConfirm("Rename Entry", "Rename", "Cancel",
			container.NewVBox(
				widget.NewLabel("New alias:"),
				newAliasEntry,
			), func(ok bool) {
				if ok {
					err := mgr.RenameEntry(oldAlias, newAliasEntry.Text)
					if err != nil {
						dialog.ShowError(err, win)
						return
					}
					refreshList()
					statusLabel.SetText(fmt.Sprintf("Renamed: %s → %s", oldAlias, newAliasEntry.Text))
				}
			}, win)
	})

	// --- Convert ---
	convertBtn := widget.NewButton("Convert", func() {
		showConvertDialog(win, statusLabel)
	})

	// --- Validate Chain ---
	validateBtn := widget.NewButton("Validate Chain", func() {
		store := mgr.GetCurrentStore()
		if store == nil {
			return
		}
		idx := selectedIndex
		if idx < 0 || idx >= len(store.Entries) {
			dialog.ShowInformation("No Selection", "Select an entry to validate", win)
			return
		}
		entry := store.Entries[idx]
		result := keystore.ValidateChain(entry)

		var msg string
		if result.Valid {
			msg = "✅ Certificate chain is valid"
		} else {
			msg = "❌ Certificate chain validation failed:\n" + strings.Join(result.Errors, "\n")
			if result.MissingIntermediate {
				msg += "\n\n⚠️ Possible missing intermediate certificate"
			}
		}
		dialog.ShowInformation("Chain Validation", msg, win)
	})

	// --- Layout ---
	toolbar := container.NewHBox(
		newBtn, openBtn, saveBtn,
		widget.NewSeparator(),
		importCertBtn, exportCertBtn,
		widget.NewSeparator(),
		genKeyBtn, csrBtn,
		widget.NewSeparator(),
		deleteBtn, renameBtn,
		widget.NewSeparator(),
		convertBtn, validateBtn,
	)

	// --- Layout ---
	listHeader := container.NewGridWithColumns(5,
		widget.NewLabelWithStyle("Alias", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabelWithStyle("Type", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabelWithStyle("Algorithm", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabelWithStyle("Size", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabelWithStyle("Created", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
	)

	listPanel := container.NewBorder(
		container.NewVBox(widget.NewLabelWithStyle("ENTRIES", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), listHeader, widget.NewSeparator()), nil, nil, nil,
		entryList,
	)

	return container.NewBorder(
		container.NewVBox(toolbar, widget.NewSeparator()),
		statusLabel,
		nil, nil,
		listPanel,
	)
}

// formatEntryDetails formats a keystore entry for display
func formatEntryDetails(entry models.KeyStoreEntry) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Alias: %s\n", entry.Alias))
	sb.WriteString(fmt.Sprintf("Type: %s\n", entry.Type))
	sb.WriteString(fmt.Sprintf("Created: %s\n", entry.CreationDate.Format("2006-01-02 15:04:05")))

	if entry.HasPrivateKey {
		sb.WriteString("Has Private Key: Yes\n")
	}
	if entry.KeyAlgorithm != "" {
		sb.WriteString(fmt.Sprintf("Key Algorithm: %s\n", entry.KeyAlgorithm))
	}
	if entry.KeySize > 0 {
		sb.WriteString(fmt.Sprintf("Key Size: %d bits\n", entry.KeySize))
	}

	sb.WriteString("\n")

	if entry.Certificate != nil {
		sb.WriteString("━━━ Certificate ━━━\n")
		sb.WriteString(fmt.Sprintf("Subject: %s\n", entry.Certificate.Subject))
		sb.WriteString(fmt.Sprintf("Issuer: %s\n", entry.Certificate.Issuer))
		sb.WriteString(fmt.Sprintf("Serial: %s\n", entry.Certificate.SerialNumber))
		sb.WriteString(fmt.Sprintf("Valid: %s → %s\n",
			entry.Certificate.NotBefore.Format("2006-01-02"),
			entry.Certificate.NotAfter.Format("2006-01-02")))
		sb.WriteString(fmt.Sprintf("Sig Algo: %s\n", entry.Certificate.SignatureAlgorithm))
		sb.WriteString(fmt.Sprintf("Key Algo: %s (%d bits)\n",
			entry.Certificate.PublicKeyAlgorithm, entry.Certificate.PublicKeyBits))

		if len(entry.Certificate.SANs) > 0 {
			sb.WriteString(fmt.Sprintf("SANs: %s\n", strings.Join(entry.Certificate.SANs, ", ")))
		}

		if entry.Certificate.IsExpired {
			sb.WriteString("⚠️  EXPIRED\n")
		}
		if entry.Certificate.IsSelfSigned {
			sb.WriteString("ℹ️  Self-Signed\n")
		}
	}

	if len(entry.CertChain) > 1 {
		sb.WriteString(fmt.Sprintf("\n━━━ Certificate Chain (%d certs) ━━━\n", len(entry.CertChain)))
		for i, cert := range entry.CertChain {
			sb.WriteString(fmt.Sprintf("  [%d] %s\n", i, cert.Subject))
		}
	}

	return sb.String()
}

// showKeyGenDialog displays the key generation wizard
func showKeyGenDialog(win fyne.Window, mgr *keystore.Manager, refresh func(), status *widget.Label) {
	aliasEntry := widget.NewEntry()
	aliasEntry.SetPlaceHolder("my-key")

	algoSelect := widget.NewSelect([]string{"RSA", "EC"}, nil)
	algoSelect.SetSelected("RSA")

	keySizeSelect := widget.NewSelect([]string{"2048", "4096"}, nil)
	keySizeSelect.SetSelected("2048")

	algoSelect.OnChanged = func(algo string) {
		if algo == "EC" {
			keySizeSelect.Options = []string{"256", "384", "521"}
			keySizeSelect.SetSelected("256")
		} else {
			keySizeSelect.Options = []string{"2048", "4096"}
			keySizeSelect.SetSelected("2048")
		}
	}

	cnEntry := widget.NewEntry()
	cnEntry.SetPlaceHolder("Common Name")
	orgEntry := widget.NewEntry()
	orgEntry.SetPlaceHolder("Organization")
	ouEntry := widget.NewEntry()
	ouEntry.SetPlaceHolder("Organizational Unit")
	locEntry := widget.NewEntry()
	locEntry.SetPlaceHolder("City")
	stEntry := widget.NewEntry()
	stEntry.SetPlaceHolder("State/Province")
	coEntry := widget.NewEntry()
	coEntry.SetPlaceHolder("Country (2-letter)")
	validEntry := widget.NewEntry()
	validEntry.SetText("365")

	formItems := []*widget.FormItem{
		{Text: "Alias", Widget: aliasEntry},
		{Text: "Algorithm", Widget: algoSelect},
		{Text: "Key Size", Widget: keySizeSelect},
		{Text: "Common Name", Widget: cnEntry},
		{Text: "Organization", Widget: orgEntry},
		{Text: "Org Unit", Widget: ouEntry},
		{Text: "Locality", Widget: locEntry},
		{Text: "State", Widget: stEntry},
		{Text: "Country", Widget: coEntry},
		{Text: "Validity (days)", Widget: validEntry},
	}

	d := dialog.NewForm("Generate Key Pair", "Generate", "Cancel", formItems,
		func(ok bool) {
			if !ok {
				return
			}

			keySize := 2048
			fmt.Sscanf(keySizeSelect.Selected, "%d", &keySize)

			validDays := 365
			fmt.Sscanf(validEntry.Text, "%d", &validDays)

			opts := models.KeyPairOptions{
				Algorithm: algoSelect.Selected,
				KeySize:   keySize,
				CommonName: cnEntry.Text,
				Org:        orgEntry.Text,
				OrgUnit:    ouEntry.Text,
				Locality:   locEntry.Text,
				State:      stEntry.Text,
				Country:    coEntry.Text,
				ValidDays:  validDays,
				Alias:      aliasEntry.Text,
			}

			_, cert, _, err := keystore.GenerateKeyPair(opts)
			if err != nil {
				dialog.ShowError(err, win)
				return
			}

			certInfo := models.CertificateInfo{
				Subject:            cert.Subject.String(),
				Issuer:             cert.Issuer.String(),
				SerialNumber:       cert.SerialNumber.String(),
				NotBefore:          cert.NotBefore,
				NotAfter:           cert.NotAfter,
				SignatureAlgorithm: cert.SignatureAlgorithm.String(),
				PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
				Raw:                cert,
			}
			entry := models.KeyStoreEntry{
				Alias:         aliasEntry.Text,
				Type:          models.EntryPrivateKey,
				HasPrivateKey: true,
				Certificate:   &certInfo,
				KeyAlgorithm:  opts.Algorithm,
				KeySize:       keySize,
				CreationDate:  time.Now(),
			}

			if mgr.GetCurrentStore() == nil {
				mgr.CreateNew(models.KeyStorePKCS12)
			}

			err = mgr.AddEntry(entry)
			if err != nil {
				dialog.ShowError(err, win)
				return
			}

			refresh()
			status.SetText("Generated key pair: " + aliasEntry.Text)
		}, win)
	d.Resize(fyne.NewSize(500, 500))
	d.Show()
}

// showCSRDialog displays the CSR generation form
func showCSRDialog(win fyne.Window, status *widget.Label) {
	algoSelect := widget.NewSelect([]string{"RSA", "EC"}, nil)
	algoSelect.SetSelected("RSA")

	keySizeSelect := widget.NewSelect([]string{"2048", "4096"}, nil)
	keySizeSelect.SetSelected("2048")

	cnEntry := widget.NewEntry()
	orgEntry := widget.NewEntry()
	ouEntry := widget.NewEntry()
	locEntry := widget.NewEntry()
	stEntry := widget.NewEntry()
	coEntry := widget.NewEntry()
	emailEntry := widget.NewEntry()
	sansEntry := widget.NewEntry()
	sansEntry.SetPlaceHolder("domain1.com, domain2.com")

	formItems := []*widget.FormItem{
		{Text: "Algorithm", Widget: algoSelect},
		{Text: "Key Size", Widget: keySizeSelect},
		{Text: "Common Name", Widget: cnEntry},
		{Text: "Organization", Widget: orgEntry},
		{Text: "Org Unit", Widget: ouEntry},
		{Text: "Locality", Widget: locEntry},
		{Text: "State", Widget: stEntry},
		{Text: "Country", Widget: coEntry},
		{Text: "Email", Widget: emailEntry},
		{Text: "SANs (comma-separated)", Widget: sansEntry},
	}

	d := dialog.NewForm("Generate CSR", "Generate", "Cancel", formItems,
		func(ok bool) {
			if !ok {
				return
			}

			keySize := 2048
			fmt.Sscanf(keySizeSelect.Selected, "%d", &keySize)

			var sans []string
			if sansEntry.Text != "" {
				for _, s := range strings.Split(sansEntry.Text, ",") {
					s = strings.TrimSpace(s)
					if s != "" {
						sans = append(sans, s)
					}
				}
			}

			opts := models.CSROptions{
				KeyAlgorithm: algoSelect.Selected,
				KeySize:      keySize,
				CommonName:   cnEntry.Text,
				Org:          orgEntry.Text,
				OrgUnit:      ouEntry.Text,
				Locality:     locEntry.Text,
				State:        stEntry.Text,
				Country:      coEntry.Text,
				Email:        emailEntry.Text,
				SANs:         sans,
			}

			result, err := keystore.GenerateCSR(opts)
			if err != nil {
				dialog.ShowError(err, win)
				return
			}

			// Save CSR
			dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
				if err != nil || writer == nil {
					return
				}
				defer writer.Close()
				writer.Write(result.CSR)

				// Also save private key
				keyPath := writer.URI().Path() + ".key"
				os.WriteFile(keyPath, result.PrivateKey, 0600)
				status.SetText(fmt.Sprintf("CSR saved. Private key: %s", keyPath))
			}, win)
		}, win)
	d.Resize(fyne.NewSize(500, 500))
	d.Show()
}

// showConvertDialog shows the keystore conversion dialog
func showConvertDialog(win fyne.Window, status *widget.Label) {
	srcTypeSelect := widget.NewSelect([]string{"JKS", "PKCS12"}, nil)
	srcTypeSelect.SetSelected("JKS")
	dstTypeSelect := widget.NewSelect([]string{"PKCS12", "JKS"}, nil)
	dstTypeSelect.SetSelected("PKCS12")
	srcPassEntry := widget.NewPasswordEntry()
	dstPassEntry := widget.NewPasswordEntry()

	var srcPath string
	srcLabel := widget.NewLabel("No file selected")

	srcBtn := widget.NewButton("Browse...", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			srcPath = reader.URI().Path()
			srcLabel.SetText(srcPath)
			reader.Close()
		}, win)
	})

	content := container.NewVBox(
		widget.NewLabel("Source KeyStore:"),
		container.NewHBox(srcBtn, srcLabel),
		container.New(layout.NewFormLayout(),
			widget.NewLabel("Source Type:"), srcTypeSelect,
			widget.NewLabel("Source Password:"), srcPassEntry,
			widget.NewLabel("Destination Type:"), dstTypeSelect,
			widget.NewLabel("Destination Password:"), dstPassEntry,
		),
	)

	var d dialog.Dialog
	onConfirm := func(ok bool) {
		if !ok || srcPath == "" {
			return
		}

		dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil || writer == nil {
				return
			}
			dstPath := writer.URI().Path()
			writer.Close()

			var srcType, dstType models.KeyStoreType
			if srcTypeSelect.Selected == "JKS" {
				srcType = models.KeyStoreJKS
			} else {
				srcType = models.KeyStorePKCS12
			}
			if dstTypeSelect.Selected == "JKS" {
				dstType = models.KeyStoreJKS
			} else {
				dstType = models.KeyStorePKCS12
			}

			opts := models.ConvertOptions{
				SourcePath:     srcPath,
				SourceType:     srcType,
				SourcePassword: srcPassEntry.Text,
				DestPath:       dstPath,
				DestType:       dstType,
				DestPassword:   dstPassEntry.Text,
			}

			err = keystore.Convert(opts)
			if err != nil {
				dialog.ShowError(err, win)
				return
			}
			status.SetText(fmt.Sprintf("Converted %s → %s", srcPath, dstPath))
		}, win)
	}

	d = dialog.NewCustomConfirm("Convert KeyStore", "Convert", "Cancel", content, onConfirm, win)

	srcPassEntry.OnSubmitted = func(s string) {
		d.Hide()
		onConfirm(true)
	}
	dstPassEntry.OnSubmitted = func(s string) {
		d.Hide()
		onConfirm(true)
	}
	d.Show()
	win.Canvas().Focus(srcPassEntry)
}

// doubleClickableGrid is a custom widget to handle double-tap events in a List row
type doubleClickableGrid struct {
	widget.BaseWidget
	grid        *fyne.Container
	onTap       func()
	onDoubleTap func()
}

func newDoubleClickableGrid(grid *fyne.Container, onTap, onDoubleTap func()) *doubleClickableGrid {
	g := &doubleClickableGrid{grid: grid, onTap: onTap, onDoubleTap: onDoubleTap}
	g.ExtendBaseWidget(g)
	return g
}

func (g *doubleClickableGrid) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(g.grid)
}

func (g *doubleClickableGrid) Tapped(_ *fyne.PointEvent) {
	if g.onTap != nil {
		g.onTap()
	}
}

func (g *doubleClickableGrid) DoubleTapped(_ *fyne.PointEvent) {
	if g.onDoubleTap != nil {
		g.onDoubleTap()
	}
}
