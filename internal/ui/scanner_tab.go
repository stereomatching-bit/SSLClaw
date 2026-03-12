package ui

import (
	"fmt"
	"image/color"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"sslclaw/internal/models"
	"sslclaw/internal/scanner"
)

// ScannerTab creates the SSL/TLS Scanner tab content
func ScannerTab(win fyne.Window) fyne.CanvasObject {
	// --- Input Section ---
	hostEntry := widget.NewEntry()
	hostEntry.SetPlaceHolder("e.g. google.com or 192.168.1.1")

	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("443")
	portEntry.SetText("443")

	starttlsSelect := widget.NewSelect(
		[]string{"None", "SMTP", "IMAP", "POP3", "FTP", "XMPP"},
		func(s string) {},
	)
	starttlsSelect.SetSelected("None")

	ipv6Check := widget.NewCheck("Use IPv6", nil)
	vulnCheck := widget.NewCheck("Check Vulnerabilities", nil)
	vulnCheck.SetChecked(true)

	timeoutEntry := widget.NewEntry()
	timeoutEntry.SetPlaceHolder("10")
	timeoutEntry.SetText("10")

	// --- Results Section ---
	protocolList := widget.NewList(
		func() int { return 0 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {},
	)

	cipherTable := widget.NewTable(
		func() (int, int) { return 0, 5 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.TableCellID, obj fyne.CanvasObject) {},
	)

	certContainer := container.NewVBox()
	certScroll := container.NewScroll(certContainer)
	
	exportChainBtn := widget.NewButton("Export Entire Chain (PEM)", func() {})
	exportChainBtn.Hide()
	
	certHeaderContainer := container.NewHBox(layout.NewSpacer(), exportChainBtn)
	
	certTabContent := container.NewBorder(certHeaderContainer, nil, nil, nil, certScroll)

	vulnText := widget.NewMultiLineEntry()
	vulnText.Disable()
	vulnText.SetMinRowsVisible(6)

	statusLabel := widget.NewLabel("Ready")
	statusLabel.TextStyle = fyne.TextStyle{Italic: true}

	progressBar := widget.NewProgressBarInfinite()
	progressBar.Hide()

	// Store results for export
	var currentResult *models.ScanResult

	// --- Export Button ---
	exportTextBtn := widget.NewButton("Export Text", func() {
		if currentResult == nil {
			dialog.ShowInformation("No Results", "Run a scan first", win)
			return
		}
		saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil || writer == nil {
				return
			}
			defer writer.Close()
			text := scanner.ExportText(*currentResult)
			writer.Write([]byte(text))
		}, win)
		saveDialog.SetFileName(fmt.Sprintf("sslclaw_%s_%d.txt", currentResult.Host, currentResult.Port))
		saveDialog.Show()
	})

	exportXMLBtn := widget.NewButton("Export XML", func() {
		if currentResult == nil {
			dialog.ShowInformation("No Results", "Run a scan first", win)
			return
		}
		saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil || writer == nil {
				return
			}
			defer writer.Close()
			xmlStr, err := scanner.ExportXML(*currentResult)
			if err != nil {
				dialog.ShowError(err, win)
				return
			}
			writer.Write([]byte(xmlStr))
		}, win)
		saveDialog.SetFileName(fmt.Sprintf("sslclaw_%s_%d.xml", currentResult.Host, currentResult.Port))
		saveDialog.Show()
	})

	// --- Scan Function ---
	doScan := func() {
		host := strings.TrimSpace(hostEntry.Text)
		if host == "" {
			dialog.ShowError(fmt.Errorf("Please enter a hostname or IP"), win)
			return
		}

		port := 443
		if p, err := strconv.Atoi(portEntry.Text); err == nil && p > 0 {
			port = p
		}

		timeout := 10
		if t, err := strconv.Atoi(timeoutEntry.Text); err == nil && t > 0 {
			timeout = t
		}

		var starttls models.STARTTLSProtocol
		switch starttlsSelect.Selected {
		case "SMTP":
			starttls = models.STARTTLS_SMTP
		case "IMAP":
			starttls = models.STARTTLS_IMAP
		case "POP3":
			starttls = models.STARTTLS_POP3
		case "FTP":
			starttls = models.STARTTLS_FTP
		case "XMPP":
			starttls = models.STARTTLS_XMPP
		default:
			starttls = models.STARTTLS_NONE
		}

		opts := models.ScanOptions{
			Host:             host,
			Port:             port,
			TimeoutSeconds:   timeout,
			STARTTLSProtocol: starttls,
			CheckVulns:       vulnCheck.Checked,
			IPv6:             ipv6Check.Checked,
		}

		statusLabel.SetText("Scanning " + host + ":" + fmt.Sprint(port) + "...")
		progressBar.Show()
		progressBar.Start()

		go func() {
			s := scanner.NewScanner(opts.TimeoutSeconds)
			result := s.ScanHost(opts)
			currentResult = &result

			// Update UI on main thread
			statusLabel.SetText(fmt.Sprintf("Scan complete in %s", result.DurationStr))
			progressBar.Stop()
			progressBar.Hide()

			if result.Error != "" {
				dialog.ShowError(fmt.Errorf("%s", result.Error), win)
				return
			}

			// Update protocol list
			protocols := result.Protocols
			protocolList.Length = func() int { return len(protocols) }
			protocolList.UpdateItem = func(id widget.ListItemID, obj fyne.CanvasObject) {
				label := obj.(*widget.Label)
				p := protocols[id]
				status := "✗"
				if p.Supported {
					status = "✓"
				}
				secLabel := ""
				if p.Supported {
					secLabel = fmt.Sprintf(" [%s]", p.Security.String())
				}
				label.SetText(fmt.Sprintf("%s  %-10s%s", status, p.Name, secLabel))
				if p.Supported {
					switch p.Security {
					case models.SecurityStrong:
						label.Importance = widget.SuccessImportance
					case models.SecurityWeak:
						label.Importance = widget.WarningImportance
					case models.SecurityInsecure:
						label.Importance = widget.DangerImportance
					default:
						label.Importance = widget.MediumImportance
					}
				} else {
					label.Importance = widget.LowImportance
				}
			}
			protocolList.Refresh()

			// Update cipher table
			ciphers := result.CipherSuites
			cipherTable.Length = func() (int, int) { return len(ciphers) + 1, 5 }
			cipherTable.UpdateCell = func(id widget.TableCellID, obj fyne.CanvasObject) {
				label := obj.(*widget.Label)
				if id.Row == 0 {
					// Header
					headers := []string{"Security", "Protocol", "Cipher Suite", "Key Exchange", "Encryption"}
					label.SetText(headers[id.Col])
					label.TextStyle = fyne.TextStyle{Bold: true}
					return
				}
				cs := ciphers[id.Row-1]
				switch id.Col {
				case 0:
					label.SetText(cs.Security.String())
					switch cs.Security {
					case models.SecurityStrong:
						label.Importance = widget.SuccessImportance
					case models.SecurityWeak:
						label.Importance = widget.WarningImportance
					case models.SecurityInsecure:
						label.Importance = widget.DangerImportance
					default:
						label.Importance = widget.MediumImportance
					}
				case 1:
					label.SetText(cs.Protocol)
				case 2:
					name := cs.Name
					if cs.IsPreferred {
						name += " ★"
					}
					label.SetText(name)
				case 3:
					label.SetText(cs.KeyExchange)
				case 4:
					label.SetText(cs.Encryption)
				}
			}
			cipherTable.SetColumnWidth(0, 100)
			cipherTable.SetColumnWidth(1, 80)
			cipherTable.SetColumnWidth(2, 350)
			cipherTable.SetColumnWidth(3, 100)
			cipherTable.SetColumnWidth(4, 150)
			cipherTable.Refresh()

			// Update certificate details
			certContainer.Objects = nil // Clear previous results
			accordion := widget.NewAccordion()
			certContainer.Add(accordion)

			if len(result.Certificates) > 0 {
				exportChainBtn.OnTapped = func() {
					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil || writer == nil {
							return
						}
						defer writer.Close()
						pemData := scanner.ExportChainPEM(result.Certificates)
						writer.Write(pemData)
					}, win)
					saveDialog.SetFileName(fmt.Sprintf("%s_chain.pem", result.Host))
					saveDialog.Show()
				}
				exportChainBtn.Show()
			} else {
				exportChainBtn.Hide()
				certContainer.Add(widget.NewLabel("No certificates found."))
			}

			for i, cert := range result.Certificates {
				var certDetails string
				certDetails += fmt.Sprintf("Subject   : %s\n", cert.Subject)
				certDetails += fmt.Sprintf("Issuer    : %s\n", cert.Issuer)
				certDetails += fmt.Sprintf("Valid     : %s → %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
				certDetails += fmt.Sprintf("Sig Algo  : %s\n", cert.SignatureAlgorithm)
				certDetails += fmt.Sprintf("Key       : %s (%d bits)\n", cert.PublicKeyAlgorithm, cert.PublicKeyBits)
				
				if len(cert.SANs) > 0 {
					certDetails += fmt.Sprintf("SANs      : %s\n", strings.Join(cert.SANs, ", "))
				}
				for algo, fp := range cert.Fingerprints {
					certDetails += fmt.Sprintf("%-10s: %s\n", algo, fp)
				}
				if cert.IsExpired {
					certDetails += "⚠️  EXPIRED\n"
				}
				if cert.IsSelfSigned {
					certDetails += "⚠️  SELF-SIGNED\n"
				}

				detailsLabel := widget.NewLabel(certDetails)

				// Create local copies of cert variable for the closures
				c := cert
				idx := i + 1

				exportPemBtn := widget.NewButton("Export PEM", func() {
					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil || writer == nil {
							return
						}
						defer writer.Close()
						pemData := scanner.ExportCertPEM(c)
						writer.Write(pemData)
					}, win)
					saveDialog.SetFileName(fmt.Sprintf("%s_cert%d.pem", result.Host, idx))
					saveDialog.Show()
				})

				exportDerBtn := widget.NewButton("Export DER", func() {
					saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
						if err != nil || writer == nil {
							return
						}
						defer writer.Close()
						derData := scanner.ExportCertDER(c)
						writer.Write(derData)
					}, win)
					saveDialog.SetFileName(fmt.Sprintf("%s_cert%d.der", result.Host, idx))
					saveDialog.Show()
				})

				title := "↳ "
				if i == 0 {
					title = "🌐 "
				}
				title += fmt.Sprintf("Certificate #%d", idx)
				if i == 0 {
					title += " (Leaf/Server)"
				} else if i == len(result.Certificates)-1 && cert.IsSelfSigned {
					title += " (Root CA)"
				} else {
					title += " (Intermediate CA)"
				}

				buttons := container.NewHBox(exportPemBtn, exportDerBtn)
				content := container.NewVBox(detailsLabel, buttons)
				
				// Calculate indent to represent visual hierarchy
				indentWidth := float32(i * 20)
				indentSpacer := canvas.NewRectangle(color.Transparent)
				indentSpacer.SetMinSize(fyne.NewSize(indentWidth, 1))

				indentedLayout := container.NewHBox(indentSpacer, content)
				
				item := widget.NewAccordionItem(title, indentedLayout)
				accordion.Append(item)

				// Open all items by default
				accordion.Open(i)
			}

			// Force layout refresh
			certContainer.Refresh()

			// Update vulnerability details
			if len(result.Vulnerabilities) > 0 {
				var vulnSB strings.Builder
				for _, vuln := range result.Vulnerabilities {
					icon := "⚠️"
					if vuln.Severity == models.SecurityInsecure {
						icon = "🔴"
					} else if vuln.Severity == models.SecurityWeak {
						icon = "🟡"
					}
					vulnSB.WriteString(fmt.Sprintf("%s [%s] %s\n   %s\n   Affected: %s\n\n",
						icon, vuln.Severity.String(), vuln.Name, vuln.Description, vuln.Affected))
				}
				vulnText.SetText(vulnSB.String())
			} else {
				vulnText.SetText("✅ No vulnerabilities detected")
			}
		}()
	}

	hostEntry.OnSubmitted = func(s string) {
		doScan()
	}
	portEntry.OnSubmitted = func(s string) {
		doScan()
	}

	// --- Scan Button ---
	scanBtn := widget.NewButton("🔍 Scan", doScan)
	scanBtn.Importance = widget.HighImportance

	// --- Batch Scan Button ---
	batchBtn := widget.NewButton("📋 Batch Scan", func() {
		showBatchDialog(win)
	})

	// --- Layout ---
	inputForm := container.NewVBox(
		widget.NewLabel("SSL/TLS Scanner"),
		container.New(layout.NewFormLayout(),
			widget.NewLabel("Host:"), hostEntry,
			widget.NewLabel("Port:"), portEntry,
			widget.NewLabel("STARTTLS:"), starttlsSelect,
			widget.NewLabel("Timeout (s):"), timeoutEntry,
		),
		container.NewHBox(ipv6Check, vulnCheck),
		container.NewHBox(scanBtn, batchBtn, layout.NewSpacer(), exportTextBtn, exportXMLBtn),
		progressBar,
		statusLabel,
	)

	// Section headers
	protoHeader := newSectionHeader("Protocol Support")
	cipherHeader := newSectionHeader("Cipher Suites")
	certHeader := newSectionHeader("Certificates")
	vulnHeader := newSectionHeader("Vulnerabilities")

	// Results tabs
	resultsTabs := container.NewAppTabs(
		container.NewTabItem("Protocols", container.NewBorder(protoHeader, nil, nil, nil, protocolList)),
		container.NewTabItem("Ciphers", container.NewBorder(cipherHeader, nil, nil, nil, cipherTable)),
		container.NewTabItem("Certificates", container.NewBorder(certHeader, nil, nil, nil, certTabContent)),
		container.NewTabItem("Vulnerabilities", container.NewBorder(vulnHeader, nil, nil, nil,
			container.NewScroll(vulnText))),
	)

	return container.NewBorder(inputForm, nil, nil, nil, resultsTabs)
}

// showBatchDialog displays the batch scan interface
func showBatchDialog(win fyne.Window) {
	targetsEntry := widget.NewMultiLineEntry()
	targetsEntry.SetPlaceHolder("Enter one host:port per line\ne.g.\ngoogle.com:443\nexample.com:443")
	targetsEntry.SetMinRowsVisible(10)

	resultsLabel := widget.NewLabel("")

	d := dialog.NewCustomConfirm("Batch Scan", "Start Scan", "Cancel",
		container.NewVBox(
			widget.NewLabel("Enter target hosts (one per line, format: host:port)"),
			targetsEntry,
			resultsLabel,
		), func(ok bool) {
			if !ok {
				return
			}

			lines := strings.Split(targetsEntry.Text, "\n")
			var targets []models.ScanOptions
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.SplitN(line, ":", 2)
				host := parts[0]
				port := 443
				if len(parts) > 1 {
					if p, err := strconv.Atoi(parts[1]); err == nil {
						port = p
					}
				}
				targets = append(targets, models.ScanOptions{
					Host:           host,
					Port:           port,
					TimeoutSeconds: 10,
					CheckVulns:     true,
				})
			}

			if len(targets) == 0 {
				dialog.ShowError(fmt.Errorf("No valid targets entered"), win)
				return
			}

			go func() {
				s := scanner.NewScanner(10)
				batch := s.ScanBatch(targets, func(done, total int) {
					resultsLabel.SetText(fmt.Sprintf("Progress: %d / %d", done, total))
				})

				// Export results
				saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
					if err != nil || writer == nil {
						return
					}
					defer writer.Close()
					text := scanner.ExportBatchText(batch)
					writer.Write([]byte(text))
				}, win)
				saveDialog.SetFileName("sslclaw_batch_report.txt")
				saveDialog.Show()
			}()
		}, win)
	d.Resize(fyne.NewSize(600, 400))
	d.Show()
}

// newSectionHeader creates a styled section header
func newSectionHeader(title string) fyne.CanvasObject {
	label := canvas.NewText(title, color.NRGBA{R: 0, G: 150, B: 255, A: 255})
	label.TextStyle = fyne.TextStyle{Bold: true}
	label.TextSize = 16
	return container.NewVBox(label, widget.NewSeparator())
}
