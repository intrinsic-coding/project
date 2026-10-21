package utils

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log/slog"
	"syscall"
	"unsafe"
)

// logCertFingerprint computes the SHA-256 Subject Public Key Info (SPKI) fingerprint
// of the leaf certificate and logs it at startup for security auditing and traffic pinning.
func logCertFingerprint(certFile, keyFile string) error {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		slog.Error("Failed to read certificates for fingerprint", "error", err)
		return err
	}
	leaf, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		slog.Error("Failed to parse certificate for fingerprint", "error", err)
		return err
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		slog.Error("Failed to marshal public key for fingerprint", "error", err)
		return err
	}
	hash := sha256.Sum256(pubKeyBytes)
	slog.Info("TRAFFIC TLS READY (Kernel TLS Mode)",
		"fingerprint", "sha256//"+base64.StdEncoding.EncodeToString(hash[:]))
	return nil
}

// raiseNoFileLimit elevates the process RLIMIT_NOFILE soft limit to 65535.
// Each active proxy connection consumes up to 4 file descriptors:
// (1 downstream TCP socket + 1 upstream TCP socket + 2 pipe ends for splice).
// Raising the descriptor ceiling prevents EMFILE / ENFILE connection dropouts under burst loads.
func raiseNoFileLimit() error {
	const LimitFD = 65535
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		slog.Error("Failed to get RLIMIT_NOFILE:", "error", err)
		return err
	}
	slog.Info("process started with NOFILE limit:", "soft", rLimit.Cur, "hard", rLimit.Max)
	if rLimit.Cur < LimitFD {
		rLimit.Cur = LimitFD
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
			slog.Error("Failed to set RLIMIT_NOFILE limit", "error", err)
			return err
		}
		slog.Info("Open file limit successfully raised", "to", "65535")
	}
	return nil
}

// UnsafeBytes performs a zero-copy, zero-allocation conversion from a string to a byte slice.
// Invariant: The resulting byte slice MUST be treated as strictly immutable (read-only);
// mutating underlying bytes will trigger undefined behavior and corrupt string memory.
func UnsafeBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			Cap int
		}{s, len(s)},
	))
}

// LogFingerprintAndLimitFD logs the TLS certificate fingerprint and ensures system descriptor limits
// are safely expanded before listening for traffic.
func LogFingerprintAndLimitFD(certFile, keyFile string) error {
	err := logCertFingerprint(certFile, keyFile)
	if err != nil {
		return err
	}
	return raiseNoFileLimit()
}
