# 🔒 SSLClaw

SSLClaw is a powerful, cross-platform SSL/TLS Scanner and KeyStore Manager built with Go and the Fyne toolkit. It provides a modern, intuitive GUI for security professionals and developers to inspect server configurations and manage cryptographic keys.

## ✨ Features

### 🔍 SSL/TLS Scanner
- **Protocol Detection**: Identifies supported protocols from SSL 3.0 to TLS 1.3.
- **Cipher Enumeration**: Lists all supported cipher suites.
- **Certificate Inspection**: Detailed view of certificates, including Subject, Issuer, Serial, Valid dates, and SANs.
- **Vulnerability Checks**: Identifies common misconfigurations and weak algorithms.
- **STARTTLS Support**: Protocols like SMTP, IMAP, POP3, and FTP are supported.

### 🔑 KeyStore Manager
- **Multi-Format Support**: Handle JKS (Java KeyStore) and PKCS#12 stores seamlessly.
- **Key Generation**: Generate RSA and EC key pairs directly within the app.
- **CSR Generation**: Create Certificate Signing Requests easily.
- **Certificate Management**: Import and export certificates in PEM or DER formats.
- **Keystore Conversion**: Convert between JKS and PKCS#12 formats.
- **Chain Validation**: Verify certificate chains for completeness and validity.

### 🎨 Modern UI
- **Responsive Design**: Built with Fyne for a fast and fluid experience.
- **Theme Support**: Switch between Dark and Light modes on the fly.

## 🚀 Building from Source

To build SSLClaw yourself, ensure you have **Go 1.21+** and a C compiler (like **GCC**) installed.

### Windows (MSYS2)
1. Install [MSYS2](https://www.msys2.org/).
2. Open "MSYS2 MinGW64" terminal and run: `pacman -S mingw-w64-x86_64-gcc`.
3. Add `C:\msys64\mingw64\bin` to your Windows PATH.
4. Run the provided build script:
   ```cmd
   build.bat
   ```
   Or build manually:
   ```cmd
   set CGO_ENABLED=1
   go build -ldflags="-s -w -H=windowsgui" -o SSLClaw.exe .
   ```

## 📦 Download

You can download the latest pre-compiled formal executable for Windows from the repository root: `SSLClaw_v1.0.0.exe`.

---
*Created with ❤️ for the security community.*
