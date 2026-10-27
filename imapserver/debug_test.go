package imapserver_test

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// lockedBuffer is a thread-safe io.Writer, like os.Stdout.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newDebugServer(t *testing.T, debug io.Writer) (*imapserver.Server, net.Addr) {
	t.Helper()

	memServer := imapmemserver.New()
	user := imapmemserver.NewUser("test-user", "test-password")
	user.Create("INBOX", nil)
	memServer.AddUser(user)

	server := imapserver.New(&imapserver.Options{
		NewSession: func(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return memServer.NewSession(), nil, nil
		},
		InsecureAuth: true,
		DebugWriter:  debug,
		Caps: imap.CapSet{
			imap.CapIMAP4rev1: {},
			imap.CapIMAP4rev2: {},
		},
	})

	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen() = %v", err)
	}
	t.Cleanup(func() { server.Close() })

	go func() {
		if err := server.Serve(ln); err != nil {
			t.Logf("Serve() = %v", err)
		}
	}()

	return server, ln.Addr()
}

func dialRaw(t *testing.T, addr net.Addr) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("net.Dial() = %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// readUntilTag reads server lines until one starts with tag+" ".
func readUntilTag(t *testing.T, br *bufio.Reader, conn net.Conn, tag string) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("readUntilTag(%q): %v", tag, err)
		}
		if strings.HasPrefix(line, tag+" ") || line == tag+"\r\n" {
			return
		}
	}
}

func TestServerDebugTraceRedaction(t *testing.T) {
	var debug lockedBuffer
	server, addr := newDebugServer(t, &debug)

	// First connection: SASL AUTHENTICATE (not-authenticated state) and an
	// APPEND carrying a synchronizing message literal.
	conn1 := dialRaw(t, addr)
	br1 := bufio.NewReader(conn1)
	readUntilTag(t, br1, conn1, "*") // greeting

	const saslIR = "AHRlc3QtdXNlcgB0ZXN0LXBhc3N3b3Jk"
	if _, err := conn1.Write([]byte("a1 AUTHENTICATE PLAIN " + saslIR + "\r\n")); err != nil {
		t.Fatal(err)
	}
	readUntilTag(t, br1, conn1, "a1")

	if _, err := conn1.Write([]byte("a2 APPEND INBOX {11}\r\n")); err != nil {
		t.Fatal(err)
	}
	readUntilTag(t, br1, conn1, "+")
	if _, err := conn1.Write([]byte("hello world\r\n")); err != nil {
		t.Fatal(err)
	}
	readUntilTag(t, br1, conn1, "a2")

	if _, err := conn1.Write([]byte("a3 LOGOUT\r\n")); err != nil {
		t.Fatal(err)
	}
	readUntilTag(t, br1, conn1, "a3")
	conn1.Close()

	// Second connection: LOGIN credentials on a fresh not-authenticated
	// session. The per-connection tracer writes to the same debug writer.
	conn2 := dialRaw(t, addr)
	br2 := bufio.NewReader(conn2)
	readUntilTag(t, br2, conn2, "*")
	if _, err := conn2.Write([]byte("b1 LOGIN \"test-user\" \"test-password\"\r\n")); err != nil {
		t.Fatal(err)
	}
	readUntilTag(t, br2, conn2, "b1")
	if _, err := conn2.Write([]byte("b2 LOGOUT\r\n")); err != nil {
		t.Fatal(err)
	}
	readUntilTag(t, br2, conn2, "b2")
	conn2.Close()

	// Shut the server down before inspecting the trace buffer, so no
	// server goroutine writes to it concurrently.
	server.Close()

	trace := debug.String()
	t.Logf("server trace:\n%s", trace)

	// Server-side directions: received commands prefixed "C: ", sent
	// responses prefixed "S: ".
	if !strings.HasPrefix(trace, "S: ") {
		t.Errorf("trace should start with the server greeting, got: %q", trace)
	}
	for _, secret := range []string{"test-password", "hello world", saslIR} {
		if strings.Contains(trace, secret) {
			t.Errorf("server trace leaks %q", secret)
		}
	}
	for _, want := range []string{
		"C: a1 AUTHENTICATE PLAIN <redacted>",
		"S: a1 OK",
		"C: a2 APPEND INBOX {11}",
		"S: a2 OK",
		"C: b1 LOGIN <redacted>",
		"S: b1 OK",
	} {
		if !strings.Contains(trace, want) {
			t.Errorf("server trace is missing %q", want)
		}
	}

	for _, line := range strings.Split(strings.TrimRight(trace, "\n"), "\n") {
		if !strings.HasPrefix(line, "C: ") && !strings.HasPrefix(line, "S: ") {
			t.Errorf("trace line without direction prefix: %q", line)
		}
	}
}
