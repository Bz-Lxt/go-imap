package imapclient_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

type recordingTracer struct {
	mu     sync.Mutex
	frames []string
}

func (r *recordingTracer) Trace(_ imap.TraceDirection, frame string) {
	r.mu.Lock()
	r.frames = append(r.frames, frame)
	r.mu.Unlock()
}

func (r *recordingTracer) join() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.frames, "\n")
}

func newTracedClientServerPair(t *testing.T) (*imapclient.Client, *recordingTracer, *recordingTracer, io.Closer) {
	memServer := imapmemserver.New()
	user := imapmemserver.NewUser(testUsername, testPassword)
	user.Create("INBOX", nil)
	memServer.AddUser(user)

	cert, err := tls.X509KeyPair([]byte(rsaCertPEM), []byte(rsaKeyPEM))
	if err != nil {
		t.Fatalf("tls.X509KeyPair() = %v", err)
	}

	serverTracer := new(recordingTracer)
	server := imapserver.New(&imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memServer.NewSession(), nil, nil
		},
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		Tracer:    serverTracer,
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: {},
			imap.CapIMAP4rev2: {},
		},
	})

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen() = %v", err)
	}
	go func() {
		if err := server.Serve(ln); err != nil {
			t.Errorf("Serve() = %v", err)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() = %v", err)
	}

	clientTracer := new(recordingTracer)
	client, err := imapclient.NewStartTLS(conn, &imapclient.Options{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		Tracer:    clientTracer,
	})
	if err != nil {
		t.Fatalf("NewStartTLS() = %v", err)
	}
	return client, clientTracer, serverTracer, server
}

// TestTracer exercises the secure protocol tracer across a STARTTLS upgrade,
// including credential redaction, literal length correlation for message
// contents, and frame continuity after the TLS upgrade.
func TestTracer(t *testing.T) {
	client, clientTracer, serverTracer, server := newTracedClientServerPair(t)
	defer client.Close()
	defer server.Close()

	if err := client.Login(testUsername, testPassword).Wait(); err != nil {
		t.Fatalf("Login().Wait() = %v", err)
	}

	appendCmd := client.Append("INBOX", int64(len(simpleRawMessage)), nil)
	if _, err := appendCmd.Write([]byte(simpleRawMessage)); err != nil {
		t.Fatalf("Append().Write() = %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("Append().Close() = %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("Append().Wait() = %v", err)
	}

	if _, err := client.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select().Wait() = %v", err)
	}

	// The connection must be fully functional: the message literal content
	// is received intact despite being masked in the trace.
	bodySection := &imap.FetchItemBodySection{}
	messages, err := client.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{bodySection},
	}).Collect()
	if err != nil {
		t.Fatalf("Fetch() = %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("len(messages) = %v, want 1", len(messages))
	}
	body := messages[0].FindBodySection(bodySection)
	if body == nil || strings.ReplaceAll(string(body), "\r\n", "\n") != simpleRawMessage {
		t.Fatalf("fetched body = %q, want %q", body, simpleRawMessage)
	}

	if err := client.Noop().Wait(); err != nil {
		t.Fatalf("Noop().Wait() = %v", err)
	}

	clientFrames := clientTracer.join()
	serverFrames := serverTracer.join()

	assertFrames := func(name, frames string) {
		t.Run(name, func(t *testing.T) {
			// Sensitive data must never appear.
			if strings.Contains(frames, testPassword) {
				t.Errorf("trace contains the password: %q", frames)
			}
			if strings.Contains(frames, "This is my letter!") {
				t.Errorf("trace contains message content: %q", frames)
			}

			// Frames must be complete: no embedded line separators or
			// binary data (TLS handshake bytes would show up here).
			for _, line := range strings.Split(frames, "\n") {
				if line == "" {
					continue
				}
				if strings.ContainsAny(line, "\r") {
					t.Errorf("frame contains CR: %q", line)
				}
				for _, ch := range line {
					if ch < 0x20 {
						t.Errorf("frame contains control character %v: %q", ch, line)
					}
				}
			}

			// Direction/tag/literal correlation.
			if !strings.Contains(frames, "STARTTLS") {
				t.Errorf("trace is missing the STARTTLS frame: %q", frames)
			}
			if !strings.Contains(frames, "LOGIN <redacted> <redacted>") {
				t.Errorf("trace is missing the redacted LOGIN frame: %q", frames)
			}
			messageLiteral := fmt.Sprintf("{%d}", len(simpleRawMessage))
			if !strings.Contains(frames, messageLiteral) {
				t.Errorf("trace is missing the message literal length %s: %q", messageLiteral, frames)
			}

			// Frames after the STARTTLS upgrade prove the tracer keeps
			// working across the TLS boundary, without handshake noise.
			for _, want := range []string{" SELECT", " FETCH", " NOOP"} {
				if !strings.Contains(frames, want) {
					t.Errorf("trace is missing post-STARTTLS frame %q: %q", want, frames)
				}
			}
		})
	}

	assertFrames("client", clientFrames)
	assertFrames("server", serverFrames)

	// Pre-upgrade frames must be present on the server side.
	if !strings.Contains(serverFrames, "IMAP server ready") {
		t.Errorf("server trace is missing the greeting: %q", serverFrames)
	}
	if !strings.Contains(serverFrames, "Begin TLS negotiation now") {
		t.Errorf("server trace is missing the STARTTLS response: %q", serverFrames)
	}

	// The tag of the redacted client LOGIN frame must correlate with the
	// tagged server response recorded on the server side.
	var loginTag string
	for _, f := range strings.Split(clientFrames, "\n") {
		if strings.Contains(f, "LOGIN <redacted>") {
			loginTag = strings.Fields(f)[0]
			break
		}
	}
	if loginTag == "" {
		t.Fatal("could not determine LOGIN tag")
	}
	if !strings.Contains(serverFrames, loginTag+" OK") {
		t.Errorf("server trace is missing the tagged completion %s OK: %q", loginTag, serverFrames)
	}
}
