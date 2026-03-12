package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"sslclaw/internal/models"
	"sync"
	"time"
)

// Scanner performs SSL/TLS scanning operations
type Scanner struct {
	Timeout time.Duration
}

// NewScanner creates a new Scanner with the given timeout
func NewScanner(timeoutSec int) *Scanner {
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	return &Scanner{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}
}

// ScanHost performs a full SSL/TLS scan of the given host:port
func (s *Scanner) ScanHost(opts models.ScanOptions) models.ScanResult {
	start := time.Now()
	host := opts.Host
	port := opts.Port
	if port <= 0 {
		port = 443
	}

	result := models.ScanResult{
		Host:     host,
		Port:     port,
		ScanTime: start,
	}

	addr := fmt.Sprintf("%s:%d", host, port)

	// Resolve IP
	network := "tcp4"
	if opts.IPv6 {
		network = "tcp6"
	}
	conn, err := net.DialTimeout(network, addr, s.Timeout)
	if err != nil {
		result.Error = fmt.Sprintf("Connection failed: %v", err)
		result.Duration = time.Since(start)
		result.DurationStr = result.Duration.String()
		return result
	}
	result.IP = conn.RemoteAddr().String()
	conn.Close()

	// If STARTTLS, upgrade connection first (tested separately per protocol)
	var starttlsDialer func(string, time.Duration) (net.Conn, error)
	if opts.STARTTLSProtocol != models.STARTTLS_NONE && opts.STARTTLSProtocol != "" {
		starttlsDialer = getSTARTTLSDialer(opts.STARTTLSProtocol)
	}

	// 1. Protocol version detection
	result.Protocols = s.detectProtocols(addr, network, starttlsDialer)

	// 2. Cipher suite enumeration
	result.CipherSuites = s.enumerateCiphers(addr, network, starttlsDialer)

	// 3. Certificate inspection
	result.Certificates = s.inspectCertificates(addr, network, starttlsDialer)

	// 4. Vulnerability checks
	if opts.CheckVulns {
		result.Vulnerabilities = checkVulnerabilities(result)
	}

	result.Duration = time.Since(start)
	result.DurationStr = result.Duration.String()
	return result
}

// ScanBatch scans multiple hosts concurrently
func (s *Scanner) ScanBatch(targets []models.ScanOptions, progressCb func(done, total int)) models.BatchScanResult {
	batch := models.BatchScanResult{
		StartTime: time.Now(),
		Total:     len(targets),
	}

	results := make([]models.ScanResult, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	done := 0

	// Limit concurrency to 10
	sem := make(chan struct{}, 10)

	for i, target := range targets {
		wg.Add(1)
		go func(idx int, opts models.ScanOptions) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := s.ScanHost(opts)
			results[idx] = r

			mu.Lock()
			done++
			if r.Error == "" {
				batch.Succeeded++
			} else {
				batch.Failed++
			}
			mu.Unlock()

			if progressCb != nil {
				progressCb(done, len(targets))
			}
		}(i, target)
	}

	wg.Wait()
	batch.Results = results
	batch.EndTime = time.Now()
	return batch
}

// dialTLS creates a TLS connection with specific config
func (s *Scanner) dialTLS(addr, network string, tlsConfig *tls.Config, starttlsDialer func(string, time.Duration) (net.Conn, error)) (*tls.Conn, error) {
	var rawConn net.Conn
	var err error

	if starttlsDialer != nil {
		rawConn, err = starttlsDialer(addr, s.Timeout)
	} else {
		rawConn, err = net.DialTimeout(network, addr, s.Timeout)
	}
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(s.Timeout))
	err = tlsConn.Handshake()
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}
