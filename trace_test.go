package imap

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewTracer(t *testing.T) {
	var buf bytes.Buffer
	tr := NewTracer(&buf)

	tr.Trace(TraceDirectionClient, "T1 STARTTLS")
	tr.Trace(TraceDirectionServer, "T1 OK Begin TLS negotiation now")
	tr.Trace(TraceDirectionClient, "T2 LOGIN <redacted> <redacted>")
	tr.Trace(TraceDirectionClient, "T3 APPEND INBOX {1234}")

	want := strings.Join([]string{
		"C 0001 T1 STARTTLS",
		"S 0002 T1 OK Begin TLS negotiation now",
		"C 0003 T2 LOGIN <redacted> <redacted>",
		"C 0004 T3 APPEND INBOX {1234}",
		"",
	}, "\n")
	if buf.String() != want {
		t.Fatalf("output = %q, want %q", buf.String(), want)
	}
}
