package imapclient_test

import (
	"bytes"
	"crypto/tls"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
)

func TestStartTLS(t *testing.T) {
	conn, server := newMemClientServerPair(t)
	defer conn.Close()
	defer server.Close()

	options := imapclient.Options{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client, err := imapclient.NewStartTLS(conn, &options)
	if err != nil {
		t.Fatalf("NewStartTLS() = %v", err)
	}
	defer client.Close()

	if err := client.Noop().Wait(); err != nil {
		t.Fatalf("Noop().Wait() = %v", err)
	}
}

// TestStartTLSDebugTrace verifies that the sanitized debug trace spans the
// cleartext and encrypted phases of a STARTTLS session, keeps direction
// prefixes and literal length markers, and never leaks credentials or
// message contents.
func TestStartTLSDebugTrace(t *testing.T) {
	conn, server := newMemClientServerPair(t)
	defer conn.Close()
	defer server.Close()

	var debug bytes.Buffer
	options := imapclient.Options{
		TLSConfig:   &tls.Config{InsecureSkipVerify: true},
		DebugWriter: &debug,
	}
	client, err := imapclient.NewStartTLS(conn, &options)
	if err != nil {
		t.Fatalf("NewStartTLS() = %v", err)
	}
	defer client.Close()

	if err := client.WaitGreeting(); err != nil {
		t.Fatalf("WaitGreeting() = %v", err)
	}
	if err := client.Login(testUsername, testPassword).Wait(); err != nil {
		t.Fatalf("Login().Wait() = %v", err)
	}

	appendCmd := client.Append("INBOX", int64(len(simpleRawMessage)), nil)
	if _, err := appendCmd.Write([]byte(simpleRawMessage)); err != nil {
		t.Fatalf("AppendCommand.Write() = %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("AppendCommand.Close() = %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("AppendCommand.Wait() = %v", err)
	}

	if err := client.Noop().Wait(); err != nil {
		t.Fatalf("Noop().Wait() = %v", err)
	}

	trace := debug.String()
	t.Logf("trace:\n%s", trace)

	// Sensitive data must never appear.
	for _, secret := range []string{testPassword, testUsername, "This is my letter!"} {
		if strings.Contains(trace, secret) {
			t.Errorf("trace leaks %q", secret)
		}
	}

	// Redaction and literal-length markers must be present.
	if !strings.Contains(trace, "LOGIN <redacted>") {
		t.Errorf("trace is missing the redacted LOGIN frame")
	}
	if !strings.Contains(trace, "APPEND INBOX {") {
		t.Errorf("trace is missing the APPEND literal length marker")
	}

	// Direction prefixes for both directions.
	if !strings.Contains(trace, "C: ") || !strings.Contains(trace, "S: ") {
		t.Errorf("trace is missing direction prefixes")
	}

	// Frames from both before and after the STARTTLS upgrade must be
	// present, and every line must be a framed trace (no TLS handshake or
	// ciphertext bytes leaking into the output).
	if !strings.Contains(trace, "STARTTLS") {
		t.Errorf("trace is missing the pre-STARTTLS cleartext phase")
	}
	if !strings.Contains(trace, "NOOP") {
		t.Errorf("trace is missing post-STARTTLS frames")
	}
	for _, line := range strings.Split(strings.TrimRight(trace, "\n"), "\n") {
		if !strings.HasPrefix(line, "C: ") && !strings.HasPrefix(line, "S: ") {
			t.Errorf("trace line without direction prefix (TLS leak?): %q", line)
		}
	}
}
