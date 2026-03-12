package scanner

import (
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"os"
	"sslclaw/internal/models"
	"strings"
	"time"
)

// ExportText generates a human-readable text report
func ExportText(result models.ScanResult) string {
	var sb strings.Builder

	sb.WriteString("=" + strings.Repeat("=", 70) + "\n")
	sb.WriteString(fmt.Sprintf("  SSLClaw Scan Report - %s:%d\n", result.Host, result.Port))
	sb.WriteString("=" + strings.Repeat("=", 70) + "\n\n")

	sb.WriteString(fmt.Sprintf("  Scan Time : %s\n", result.ScanTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("  Duration  : %s\n", result.DurationStr))
	sb.WriteString(fmt.Sprintf("  IP Address: %s\n", result.IP))
	sb.WriteString("\n")

	// Protocols
	sb.WriteString("-" + strings.Repeat("-", 70) + "\n")
	sb.WriteString("  Protocol Support\n")
	sb.WriteString("-" + strings.Repeat("-", 70) + "\n")
	for _, proto := range result.Protocols {
		status := "Not Supported"
		if proto.Supported {
			status = fmt.Sprintf("Supported    [%s]", proto.Security.String())
		}
		sb.WriteString(fmt.Sprintf("  %-10s : %s\n", proto.Name, status))
	}
	sb.WriteString("\n")

	// Cipher Suites
	sb.WriteString("-" + strings.Repeat("-", 70) + "\n")
	sb.WriteString("  Cipher Suites\n")
	sb.WriteString("-" + strings.Repeat("-", 70) + "\n")
	for _, cs := range result.CipherSuites {
		preferred := ""
		if cs.IsPreferred {
			preferred = " *PREFERRED*"
		}
		sb.WriteString(fmt.Sprintf("  [%s] %-8s %s%s\n",
			cs.Security.String(), cs.Protocol, cs.Name, preferred))
	}
	sb.WriteString("\n")

	// Certificates
	sb.WriteString("-" + strings.Repeat("-", 70) + "\n")
	sb.WriteString("  Certificates\n")
	sb.WriteString("-" + strings.Repeat("-", 70) + "\n")
	for i, cert := range result.Certificates {
		sb.WriteString(fmt.Sprintf("  Certificate #%d:\n", i+1))
		sb.WriteString(fmt.Sprintf("    Subject   : %s\n", cert.Subject))
		sb.WriteString(fmt.Sprintf("    Issuer    : %s\n", cert.Issuer))
		sb.WriteString(fmt.Sprintf("    Serial    : %s\n", cert.SerialNumber))
		sb.WriteString(fmt.Sprintf("    Not Before: %s\n", cert.NotBefore.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("    Not After : %s\n", cert.NotAfter.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("    Sig Algo  : %s\n", cert.SignatureAlgorithm))
		sb.WriteString(fmt.Sprintf("    Key Algo  : %s (%d bits)\n", cert.PublicKeyAlgorithm, cert.PublicKeyBits))
		if len(cert.SANs) > 0 {
			sb.WriteString(fmt.Sprintf("    SANs      : %s\n", strings.Join(cert.SANs, ", ")))
		}
		for algo, fp := range cert.Fingerprints {
			sb.WriteString(fmt.Sprintf("    %-10s: %s\n", algo, fp))
		}
		if cert.IsExpired {
			sb.WriteString("    *** EXPIRED ***\n")
		}
		if cert.IsSelfSigned {
			sb.WriteString("    *** SELF-SIGNED ***\n")
		}
		sb.WriteString("\n")
	}

	// Vulnerabilities
	if len(result.Vulnerabilities) > 0 {
		sb.WriteString("-" + strings.Repeat("-", 70) + "\n")
		sb.WriteString("  Vulnerabilities\n")
		sb.WriteString("-" + strings.Repeat("-", 70) + "\n")
		for _, vuln := range result.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", vuln.Severity.String(), vuln.Name))
			sb.WriteString(fmt.Sprintf("    %s\n", vuln.Description))
			sb.WriteString(fmt.Sprintf("    Affected: %s\n\n", vuln.Affected))
		}
	}

	sb.WriteString("=" + strings.Repeat("=", 70) + "\n")
	sb.WriteString("  End of Report\n")
	sb.WriteString("=" + strings.Repeat("=", 70) + "\n")

	return sb.String()
}

// XMLScanResult is the XML wrapper for export
type XMLScanResult struct {
	XMLName xml.Name          `xml:"sslclaw-report"`
	Version string            `xml:"version,attr"`
	Result  models.ScanResult `xml:"scanResult"`
}

// ExportXML generates an XML report
func ExportXML(result models.ScanResult) (string, error) {
	wrapped := XMLScanResult{
		Version: "1.0",
		Result:  result,
	}

	data, err := xml.MarshalIndent(wrapped, "", "  ")
	if err != nil {
		return "", fmt.Errorf("XML marshal failed: %v", err)
	}

	return xml.Header + string(data), nil
}

// ExportToFile writes a report to a file
func ExportToFile(result models.ScanResult, path string, format string) error {
	var content string
	var err error

	switch strings.ToLower(format) {
	case "xml":
		content, err = ExportXML(result)
		if err != nil {
			return err
		}
	default:
		content = ExportText(result)
	}

	return os.WriteFile(path, []byte(content), 0644)
}

// ExportBatchText generates a summary text report for batch results
func ExportBatchText(batch models.BatchScanResult) string {
	var sb strings.Builder

	sb.WriteString("=" + strings.Repeat("=", 70) + "\n")
	sb.WriteString("  SSLClaw Batch Scan Report\n")
	sb.WriteString("=" + strings.Repeat("=", 70) + "\n\n")

	sb.WriteString(fmt.Sprintf("  Total Hosts : %d\n", batch.Total))
	sb.WriteString(fmt.Sprintf("  Succeeded   : %d\n", batch.Succeeded))
	sb.WriteString(fmt.Sprintf("  Failed      : %d\n", batch.Failed))
	sb.WriteString(fmt.Sprintf("  Duration    : %s\n\n", batch.EndTime.Sub(batch.StartTime).String()))

	for _, result := range batch.Results {
		sb.WriteString(ExportText(result))
		sb.WriteString("\n\n")
	}

	return sb.String()
}

// ExportCertPEM returns the PEM encoded version of a certificate
func ExportCertPEM(certInfo models.CertificateInfo) []byte {
	if certInfo.Raw == nil {
		return nil
	}
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certInfo.Raw.Raw,
	}
	return pem.EncodeToMemory(pemBlock)
}

// ExportCertDER returns the DER encoded version of a certificate
func ExportCertDER(certInfo models.CertificateInfo) []byte {
	if certInfo.Raw == nil {
		return nil
	}
	return certInfo.Raw.Raw
}

// ExportChainPEM returns the PEM encoded version of a full certificate chain
func ExportChainPEM(certs []models.CertificateInfo) []byte {
	var sb strings.Builder
	for _, cert := range certs {
		pemBytes := ExportCertPEM(cert)
		if pemBytes != nil {
			sb.Write(pemBytes)
		}
	}
	return []byte(sb.String())
}
