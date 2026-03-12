package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"

	"sslclaw/internal/models"
)

// getSTARTTLSDialer returns a function that negotiates STARTTLS before returning the connection
func getSTARTTLSDialer(protocol models.STARTTLSProtocol) func(string, time.Duration) (net.Conn, error) {
	switch protocol {
	case models.STARTTLS_SMTP:
		return dialSTARTTLS_SMTP
	case models.STARTTLS_IMAP:
		return dialSTARTTLS_IMAP
	case models.STARTTLS_POP3:
		return dialSTARTTLS_POP3
	case models.STARTTLS_FTP:
		return dialSTARTTLS_FTP
	case models.STARTTLS_XMPP:
		return dialSTARTTLS_XMPP
	default:
		return nil
	}
}

// dialSTARTTLS_SMTP negotiates SMTP STARTTLS
func dialSTARTTLS_SMTP(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read server greeting
	line, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMTP greeting failed: %v", err)
	}
	if !strings.HasPrefix(line, "220") {
		conn.Close()
		return nil, fmt.Errorf("unexpected SMTP greeting: %s", line)
	}

	// Send EHLO
	fmt.Fprintf(conn, "EHLO sslclaw\r\n")

	// Read EHLO response (multi-line)
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("EHLO response failed: %v", err)
		}
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}

	// Send STARTTLS
	fmt.Fprintf(conn, "STARTTLS\r\n")

	// Read STARTTLS response
	line, err = reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("STARTTLS response failed: %v", err)
	}
	if !strings.HasPrefix(line, "220") {
		conn.Close()
		return nil, fmt.Errorf("STARTTLS not supported: %s", line)
	}

	return conn, nil
}

// dialSTARTTLS_IMAP negotiates IMAP STARTTLS
func dialSTARTTLS_IMAP(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read server greeting
	line, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("IMAP greeting failed: %v", err)
	}
	if !strings.Contains(line, "OK") {
		conn.Close()
		return nil, fmt.Errorf("unexpected IMAP greeting: %s", line)
	}

	// Send STARTTLS
	fmt.Fprintf(conn, "a001 STARTTLS\r\n")

	// Read response
	line, err = reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("STARTTLS response failed: %v", err)
	}
	if !strings.Contains(line, "OK") {
		conn.Close()
		return nil, fmt.Errorf("STARTTLS not supported: %s", line)
	}

	return conn, nil
}

// dialSTARTTLS_POP3 negotiates POP3 STLS
func dialSTARTTLS_POP3(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read server greeting
	line, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("POP3 greeting failed: %v", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		conn.Close()
		return nil, fmt.Errorf("unexpected POP3 greeting: %s", line)
	}

	// Send STLS
	fmt.Fprintf(conn, "STLS\r\n")

	// Read response
	line, err = reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("STLS response failed: %v", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		conn.Close()
		return nil, fmt.Errorf("STLS not supported: %s", line)
	}

	return conn, nil
}

// dialSTARTTLS_FTP negotiates FTP AUTH TLS
func dialSTARTTLS_FTP(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	// Read server greeting
	line, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("FTP greeting failed: %v", err)
	}
	if !strings.HasPrefix(line, "220") {
		conn.Close()
		return nil, fmt.Errorf("unexpected FTP greeting: %s", line)
	}

	// Send AUTH TLS
	fmt.Fprintf(conn, "AUTH TLS\r\n")

	// Read response
	line, err = reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("AUTH TLS response failed: %v", err)
	}
	if !strings.HasPrefix(line, "234") {
		conn.Close()
		return nil, fmt.Errorf("AUTH TLS not supported: %s", line)
	}

	return conn, nil
}

// dialSTARTTLS_XMPP negotiates XMPP STARTTLS
func dialSTARTTLS_XMPP(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	host, _, _ := net.SplitHostPort(addr)

	// Send stream header
	streamHeader := fmt.Sprintf(
		`<?xml version='1.0'?><stream:stream xmlns='jabber:client' `+
			`xmlns:stream='http://etherx.jabber.org/streams' to='%s' version='1.0'>`, host)
	fmt.Fprint(conn, streamHeader)

	// Read until we find starttls feature or timeout
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("XMPP stream failed: %v", err)
	}
	response := string(buf[:n])

	if !strings.Contains(response, "starttls") {
		conn.Close()
		return nil, fmt.Errorf("XMPP STARTTLS not supported")
	}

	// Send STARTTLS
	fmt.Fprint(conn, `<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>`)

	// Read proceed response
	n, err = conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("XMPP STARTTLS response failed: %v", err)
	}
	response = string(buf[:n])

	if !strings.Contains(response, "proceed") {
		conn.Close()
		return nil, fmt.Errorf("XMPP STARTTLS rejected")
	}

	return conn, nil
}
