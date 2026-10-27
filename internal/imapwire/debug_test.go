package imapwire

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
)

// chunkReader returns scripted chunks verbatim, to emulate arbitrary network
// fragmentation.
type chunkReader struct {
	chunks [][]byte
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if len(r.chunks[0]) == 0 {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

func newTestTracer(side ConnSide) (*DebugTracer, *bytes.Buffer) {
	var buf bytes.Buffer
	return NewDebugTracer(&buf, side), &buf
}

// feedChunks pushes chunks through a direction's consume function.
func feedChunks(s *debugStream, chunks ...[]byte) {
	for _, chunk := range chunks {
		s.consume(chunk)
	}
}

func TestDebugTracerNil(t *testing.T) {
	if tr := NewDebugTracer(nil, ConnSideClient); tr != nil {
		t.Fatalf("NewDebugTracer(nil) = %v, want nil", tr)
	}
}

func TestDebugDirectionAndFragmentation(t *testing.T) {
	tr, out := newTestTracer(ConnSideClient)

	// A command split across three TCP segments.
	feedChunks(tr.send, []byte("T1 NO"), []byte("OP\r"), []byte("\n"))
	// A response split across CRLF and interleaved with another frame.
	feedChunks(tr.recv, []byte("* OK greeting\r\nT1 OK N"), []byte("OOP completed\r\n"))

	want := "" +
		"C: T1 NOOP\n" +
		"S: * OK greeting\n" +
		"S: T1 OK NOOP completed\n"
	if got := out.String(); got != want {
		t.Fatalf("trace = %q, want %q", got, want)
	}
}

func TestDebugServerSidePrefixes(t *testing.T) {
	tr, out := newTestTracer(ConnSideServer)

	feedChunks(tr.recv, []byte("T1 NOOP\r\n"))
	feedChunks(tr.send, []byte("T1 OK NOOP completed\r\n"))

	want := "C: T1 NOOP\nS: T1 OK NOOP completed\n"
	if got := out.String(); got != want {
		t.Fatalf("trace = %q, want %q", got, want)
	}
}

func TestDebugLoneLF(t *testing.T) {
	tr, out := newTestTracer(ConnSideClient)
	feedChunks(tr.send, []byte("T1 NOOP\n"))
	if got, want := out.String(), "C: T1 NOOP\n"; got != want {
		t.Fatalf("trace = %q, want %q", got, want)
	}
}

func TestDebugLoginRedacted(t *testing.T) {
	tr, out := newTestTracer(ConnSideClient)
	feedChunks(tr.send, []byte("T2 LOGIN \"alice\" \"s3cret!\"\r\n"))
	if got := out.String(); got != "C: T2 LOGIN <redacted>\n" {
		t.Fatalf("trace = %q", got)
	}
	if bytes.Contains(out.Bytes(), []byte("s3cret")) || bytes.Contains(out.Bytes(), []byte("alice")) {
		t.Fatalf("trace leaks LOGIN credentials: %q", out.String())
	}
}

func TestDebugLoginLiteralRedacted(t *testing.T) {
	tr, out := newTestTracer(ConnSideClient)
	// Username/password encoded as literals, with a sync continuation
	// exchanged in between.
	feedChunks(tr.send,
		[]byte("T2 LOGIN {5}"), []byte("\r\n"),
		[]byte("alice"),
		[]byte(" {7}\r\n"),
		[]byte("s3cret!"),
		[]byte("\r\n"))
	feedChunks(tr.recv, []byte("+ Ready for literal data\r\n"), []byte("+ Ready for literal data\r\n"))

	if got, wantSub := out.String(), "C: T2 LOGIN <redacted>\n"; !bytes.Contains(out.Bytes(), []byte(wantSub)) {
		t.Fatalf("trace = %q, want substring %q", got, wantSub)
	}
	if bytes.Contains(out.Bytes(), []byte("s3cret")) || bytes.Contains(out.Bytes(), []byte("alice")) {
		t.Fatalf("trace leaks LOGIN literal data: %q", out.String())
	}
}

func TestDebugLiteralContentReplacedByLength(t *testing.T) {
	tr, out := newTestTracer(ConnSideClient)

	// APPEND with a non-sync literal followed by more parameters.
	feedChunks(tr.send,
		[]byte("A1 APPEND INBOX {5}"), []byte("\r\n"),
		[]byte("hello"),
		[]byte(" FLAGS (\\Seen)\r\n"))
	want := "C: A1 APPEND INBOX {5} FLAGS (\\Seen)\n"
	if got := out.String(); got != want {
		t.Fatalf("trace = %q, want %q", got, want)
	}

	// A server FETCH with two literals: message data and headers.
	feedChunks(tr.recv,
		[]byte("* 1 FETCH (BODY[] {5}\r\n"),
		[]byte("hello"),
		[]byte(" BINARY[] {3}\r\n"),
		[]byte("abc"),
		[]byte(" FLAGS (\\Seen))\r\n"))
	got := out.String()
	if !bytes.Contains(out.Bytes(), []byte("S: * 1 FETCH (BODY[] {5} BINARY[] {3} FLAGS (\\Seen))\n")) {
		t.Fatalf("trace = %q", got)
	}
	if bytes.Contains(out.Bytes(), []byte("hello")) {
		t.Fatalf("trace leaks literal payload: %q", got)
	}
}

func TestDebugLiteral8AndNonSyncMarker(t *testing.T) {
	tr, out := newTestTracer(ConnSideServer)
	// Server sending a literal8 non-synchronizing literal.
	feedChunks(tr.send,
		[]byte("* 1 FETCH (RFC8970.MAILBOXID {5+}\r\n"),
		[]byte("inbox"),
		[]byte(")\r\n"))
	want := "S: * 1 FETCH (RFC8970.MAILBOXID {5+})\n"
	// {~N+} form
	feedChunks(tr.send, []byte("* 2 FETCH (BINARY[0] {~3+}\r\n"), []byte("abc"), []byte(")\r\n"))
	if got := out.String(); !bytes.Contains(out.Bytes(), []byte(want)) ||
		!bytes.Contains(out.Bytes(), []byte("S: * 2 FETCH (BINARY[0] {~3+})\n")) {
		t.Fatalf("trace = %q", got)
	}
	if bytes.Contains(out.Bytes(), []byte("inbox")) || bytes.Contains(out.Bytes(), []byte("abc")) {
		t.Fatalf("trace leaks literal payload: %q", out.String())
	}
}

func TestDebugSASLWithoutInitialResponse(t *testing.T) {
	tr, out := newTestTracer(ConnSideClient)

	feedChunks(tr.send, []byte("T1 AUTHENTICATE PLAIN\r\n"))
	feedChunks(tr.recv, []byte("+ \r\n")) // empty continuation
	feedChunks(tr.send, []byte("AHRlc3QtdXNlcgB0ZXN0LXBhc3N3b3Jk\r\n"))
	feedChunks(tr.recv, []byte("+ c29tZS1jaGFsbGVuZ2U=\r\n"))
	feedChunks(tr.send, []byte("dGVzdC1yZXNwb25zZQ==\r\n"))
	feedChunks(tr.recv, []byte("T1 OK PLAIN authentication successful\r\n"))

	want := "" +
		"C: T1 AUTHENTICATE PLAIN\n" +
		"S: + \n" +
		"C: <SASL response redacted>\n" +
		"S: + <redacted>\n" +
		"C: <SASL response redacted>\n" +
		"S: T1 OK PLAIN authentication successful\n"
	if got := out.String(); got != want {
		t.Fatalf("trace = %q, want %q", got, want)
	}
	for _, secret := range []string{"dXNlcg", "cGFzc3", "c29tZS1jaGFsbGVuZ2U", "dGVzdC1yZXNwb25zZQ"} {
		if bytes.Contains(out.Bytes(), []byte(secret)) {
			t.Fatalf("trace leaks SASL data %q: %q", secret, out.String())
		}
	}

	// After completion, a literal continuation must not be redacted.
	feedChunks(tr.recv, []byte("+ Ready for literal data\r\n"))
	if !bytes.HasSuffix(out.Bytes(), []byte("S: + Ready for literal data\n")) {
		t.Fatalf("literal continuation redacted after SASL: %q", out.String())
	}
}

func TestDebugSASLInitialResponse(t *testing.T) {
	tr, out := newTestTracer(ConnSideClient)

	secret := "AHRlc3QtdXNlcgB0ZXN0LXBhc3N3b3Jk"
	feedChunks(tr.send, []byte("T1 AUTHENTICATE PLAIN "+secret+"\r\n"))
	feedChunks(tr.recv, []byte("T1 OK PLAIN authentication successful\r\n"))

	want := "C: T1 AUTHENTICATE PLAIN <redacted>\nS: T1 OK PLAIN authentication successful\n"
	if got := out.String(); got != want {
		t.Fatalf("trace = %q, want %q", got, want)
	}
}

func TestDebugSASLCancel(t *testing.T) {
	tr, out := newTestTracer(ConnSideServer)

	feedChunks(tr.recv, []byte("T1 AUTHENTICATE PLAIN\r\n"))
	feedChunks(tr.send, []byte("+ \r\n"))
	feedChunks(tr.recv, []byte("*\r\n")) // cancellation
	feedChunks(tr.send, []byte("T1 BAD AUTHENTICATE cancelled\r\n"))

	want := "C: T1 AUTHENTICATE PLAIN\nS: + \nC: *\nS: T1 BAD AUTHENTICATE cancelled\n"
	if got := out.String(); got != want {
		t.Fatalf("trace = %q, want %q", got, want)
	}

	// SASL state cleared: next continuation isn't treated as a challenge.
	feedChunks(tr.send, []byte("+ Ready for literal data\r\n"))
	if !bytes.HasSuffix(out.Bytes(), []byte("S: + Ready for literal data\n")) {
		t.Fatalf("SASL state not cleared: %q", out.String())
	}
}

func TestDebugSASLFailureClearsState(t *testing.T) {
	tr, out := newTestTracer(ConnSideClient)

	feedChunks(tr.send, []byte("T1 AUTHENTICATE PLAIN AHRlc3Q=\r\n"))
	feedChunks(tr.recv, []byte("T1 NO Authentication failed\r\n"))
	feedChunks(tr.recv, []byte("+ Ready for literal data\r\n"))

	if got := out.String(); !bytes.HasSuffix(out.Bytes(), []byte("S: + Ready for literal data\n")) {
		t.Fatalf("SASL state not cleared on failure: %q", got)
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDebugSinkErrorIsIsolated(t *testing.T) {
	sinkErr := errors.New("debug sink broken")
	tr := NewDebugTracer(failingWriter{err: sinkErr}, ConnSideClient)

	var conn bytes.Buffer
	rw := tr.Wrap(&conn)

	// A failing debug sink must not change the connection write result.
	if _, err := rw.Write([]byte("T1 NOOP\r\n")); err != nil {
		t.Fatalf("Write() = %v, want nil despite sink failure", err)
	}
	if got, want := conn.String(), "T1 NOOP\r\n"; got != want {
		t.Fatalf("connection data = %q, want %q", got, want)
	}

	// Reads must still work with a broken sink.
	src := &chunkReader{chunks: [][]byte{[]byte("* OK greeting\r\n")}}
	rw2 := tr.Wrap(struct {
		io.Reader
		io.Writer
	}{Reader: src, Writer: io.Discard})
	if _, err := io.Copy(io.Discard, rw2); err != nil {
		t.Fatalf("read with broken debug sink: %v", err)
	}
}

func TestDebugConcurrentDirections(t *testing.T) {
	tr, out := newTestTracer(ConnSideClient)

	const frames = 200
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < frames; i++ {
			tr.send.consume([]byte("T1 APPEND INBOX {5}\r\nhello FLAGS (\\Seen)\r\n"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < frames; i++ {
			tr.recv.consume([]byte("* 1 FETCH (BODY[] {5}\r\nhello UID 1)\r\n"))
		}
	}()
	wg.Wait()

	// Every output line must be a complete, prefixed frame: no
	// interleaving between directions, and literal data must be gone.
	for _, line := range bytes.Split(bytes.TrimRight(out.Bytes(), "\n"), []byte("\n")) {
		if !(bytes.HasPrefix(line, []byte("C: T1 APPEND INBOX {5} FLAGS (\\Seen)")) ||
			bytes.HasPrefix(line, []byte("S: * 1 FETCH (BODY[] {5} UID 1)"))) {
			t.Fatalf("interleaved or corrupted trace line: %q", line)
		}
	}
}

func TestDebugTracerReusedAcrossUpgrade(t *testing.T) {
	tr, out := newTestTracer(ConnSideClient)

	var plainConn bytes.Buffer
	tr.Wrap(&plainConn)
	// A frame fragmented across the (simulated) STARTTLS upgrade: only its
	// beginning is seen before the reset.
	tr.send.consume([]byte("T2 NO"))

	var tlsConn bytes.Buffer
	rw := tr.Wrap(&tlsConn)
	// The remainder arrives on the upgraded connection and must be
	// reassembled into one frame using the preserved state.
	tr.send.consume([]byte("OP\r\n"))

	if got, want := out.String(), "C: T2 NOOP\n"; got != want {
		t.Fatalf("trace = %q, want %q", got, want)
	}
	if _, err := rw.Write([]byte("T3 NOOP\r\n")); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if got, want := out.String(), "C: T2 NOOP\nC: T3 NOOP\n"; got != want {
		t.Fatalf("trace = %q, want %q", got, want)
	}
}

func TestDebugReaderWrapper(t *testing.T) {
	tr, out := newTestTracer(ConnSideClient)
	r := tr.Wrap(struct {
		io.Reader
		io.Writer
	}{
		Reader: &chunkReader{chunks: [][]byte{
			[]byte("* OK gree"),
			[]byte("ting\r\n"),
		}},
		Writer: io.Discard,
	})
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "S: * OK greeting\n"; got != want {
		t.Fatalf("trace = %q, want %q", got, want)
	}
}

func TestParseLiteralSuffix(t *testing.T) {
	cases := []struct {
		line string
		size int64
		ok   bool
	}{
		{"A1 APPEND INBOX {42}", 42, true},
		{"A1 APPEND INBOX {42+}", 42, true},
		{"* 1 FETCH (BINARY[] {~42+}", 42, true},
		{"{~0}", 0, true},
		{"{}", 0, false},
		{"{x}", 0, false},
		{"T1 NOOP", 0, false},
		{"T1 LOGIN \"{5}\"", 0, false}, // quoted string, not a literal
	}
	for _, tc := range cases {
		size, ok := parseLiteralSuffix([]byte(tc.line), 0)
		if ok != tc.ok || (ok && size != tc.size) {
			t.Errorf("parseLiteralSuffix(%q) = (%v, %v), want (%v, %v)", tc.line, size, ok, tc.size, tc.ok)
		}
	}
}

func TestParseLiteralSuffixAfterConsumedLiteral(t *testing.T) {
	// "T2 LOGIN {5} {7}" with the first marker already consumed: it must
	// not be detected again when the frame ends right after the second
	// payload.
	line := []byte("T2 LOGIN {5} {7}")
	if _, ok := parseLiteralSuffix(line, 0); !ok {
		t.Fatalf("first detection failed")
	}
	firstMark := len("T2 LOGIN {5} ") // index at which "{7}" starts
	// After skipping the first payload, only markers starting at or after
	// firstMark... note "{7}" here starts exactly at firstMark.
	if _, ok := parseLiteralSuffix(line, firstMark); !ok {
		t.Fatalf("second literal marker not detected")
	}
	// Once the second payload is consumed too, no marker may be detected.
	if _, ok := parseLiteralSuffix(line, len(line)); ok {
		t.Fatalf("consumed marker detected again")
	}
	// A marker ending before the floor is ignored (re-detection guard).
	if _, ok := parseLiteralSuffix([]byte("T2 LOGIN {5}"), len("T2 LOGIN {5}")); ok {
		t.Fatalf("already-consumed marker detected again")
	}
}
