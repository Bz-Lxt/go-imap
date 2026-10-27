package imaptrace

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/internal/imapwire"
)

type recordedFrame struct {
	dir   imap.TraceDirection
	frame string
}

type recordingSink struct {
	mu     sync.Mutex
	frames []recordedFrame
}

func (s *recordingSink) Trace(dir imap.TraceDirection, frame string) {
	s.mu.Lock()
	s.frames = append(s.frames, recordedFrame{dir: dir, frame: frame})
	s.mu.Unlock()
}

func (s *recordingSink) get() []recordedFrame {
	s.mu.Lock()
	defer s.mu.Unlock()
	frames := make([]recordedFrame, len(s.frames))
	copy(frames, s.frames)
	return frames
}

// harness wires a tracer between an in-memory receive buffer and a discard
// sink. Writes go to the local side's send direction, reads to the opposite
// direction.
type harness struct {
	t       *Tracer
	rw      io.ReadWriter
	recvBuf *bytes.Buffer
}

func newHarness(side imapwire.ConnSide) (*harness, *recordingSink) {
	sink := new(recordingSink)
	t := New(sink, side)
	recvBuf := new(bytes.Buffer)
	rw := t.Wrap(struct {
		io.Reader
		io.Writer
	}{
		Reader: recvBuf,
		Writer: io.Discard,
	})
	return &harness{t: t, rw: rw, recvBuf: recvBuf}, sink
}

// writeChunks sends data in the given chunk sizes, fragmenting arbitrarily.
func (h *harness) writeChunks(t *testing.T, data []byte, sizes ...int) {
	t.Helper()
	for i := 0; len(data) > 0; i++ {
		n := sizes[i%len(sizes)]
		if n > len(data) {
			n = len(data)
		}
		if _, err := h.rw.Write(data[:n]); err != nil {
			t.Fatalf("Write() = %v", err)
		}
		data = data[n:]
	}
}

func (h *harness) readByteByByte(t *testing.T) []byte {
	t.Helper()
	var got []byte
	p := make([]byte, 1)
	for {
		n, err := h.rw.Read(p)
		got = append(got, p[:n]...)
		if err == io.EOF {
			return got
		}
		if err != nil {
			t.Fatalf("Read() = %v", err)
		}
	}
}

func (h *harness) feedReceived(t *testing.T, data string) {
	t.Helper()
	h.recvBuf.WriteString(data)
	got := h.readByteByByte(t)
	if string(got) != data {
		t.Fatalf("tracer altered received data: got %q, want %q", got, data)
	}
}

func findFrame(frames []recordedFrame, want string) *recordedFrame {
	for i := range frames {
		if frames[i].frame == want {
			return &frames[i]
		}
	}
	return nil
}

func TestReassembleFragmentedFrame(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideClient)

	// Fragment the server greeting one byte at a time.
	raw := "* OK [CAPABILITY IMAP4rev2] IMAP4rev2 ready\r\n"
	h.recvBuf.WriteString(raw)
	got := h.readByteByByte(t)
	if string(got) != raw {
		t.Fatalf("Read() altered data: got %q", got)
	}

	frames := sink.get()
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	if frames[0].dir != imap.TraceDirectionServer {
		t.Errorf("dir = %v, want server", frames[0].dir)
	}
	if frames[0].frame != "* OK [CAPABILITY IMAP4rev2] IMAP4rev2 ready" {
		t.Errorf("frame = %q", frames[0].frame)
	}
}

func TestLiteralShowsSizeNotContent(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideClient)

	// Server FETCH response containing message content, fragmented.
	h.feedReceived(t, "* 1 FETCH (BODY[] {5}\r\nHello FLAGS (\\Seen))\r\n")

	frames := sink.get()
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	want := "* 1 FETCH (BODY[] {5} FLAGS (\\Seen))"
	if frames[0].frame != want {
		t.Errorf("frame = %q, want %q", frames[0].frame, want)
	}
}

func TestClientLiteralSending(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideClient)

	// APPEND with a non-synchronizing literal, fragmented across chunks.
	h.writeChunks(t, []byte("T5 APPEND INBOX (\\Seen) {11+}\r\nhello world\r\n"), 3, 7, 1, 100)

	frames := sink.get()
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	want := "T5 APPEND INBOX (\\Seen) {11}"
	if frames[0].frame != want {
		t.Errorf("frame = %q, want %q", frames[0].frame, want)
	}
	if frames[0].dir != imap.TraceDirectionClient {
		t.Errorf("dir = %v, want client", frames[0].dir)
	}
}

func TestLiteral8Header(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideClient)
	h.writeChunks(t, []byte("T6 APPEND INBOX {~3+}\r\nabc\r\n"), 2, 5)

	frames := sink.get()
	if len(frames) != 1 || frames[0].frame != "T6 APPEND INBOX {3}" {
		t.Fatalf("frames = %#v", frames)
	}
}

func TestLoginQuotedRedacted(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideClient)
	h.writeChunks(t, []byte("T1 LOGIN \"alice\" \"p@ss w0rd\"\r\n"), 4, 4)

	frames := sink.get()
	want := "T1 LOGIN " + redacted + " " + redacted
	if findFrame(frames, want) == nil {
		t.Fatalf("redacted LOGIN frame not found, got: %#v", frames)
	}
}

func TestLoginLiteralRedacted(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideClient)

	// Synchronizing literals: headers and payloads interleaved with the
	// continuation acknowledgements coming from the other direction.
	h.writeChunks(t, []byte("T2 LOGIN {5}\r\nalice {9}\r\np@ss w0rd\r\n"), 1, 4, 2, 6, 3, 5, 100)
	h.feedReceived(t, "+ Ready for literal data\r\n+ Ready for literal data\r\n")

	var login string
	for _, f := range sink.get() {
		if f.dir == imap.TraceDirectionClient {
			login = f.frame
		}
	}
	want := "T2 LOGIN " + redacted + " " + redacted
	if login != want {
		t.Fatalf("client frame = %q, want %q", login, want)
	}
}

func TestAuthenticateWithInitialResponse(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideClient)

	h.writeChunks(t, []byte("T3 AUTHENTICATE PLAIN AHVzZXIAcGFzcw\r\n"), 2, 3, 100)
	// SASL state must be reset by the tagged completion.
	h.feedReceived(t, "T3 OK PLAIN authentication successful\r\n")
	// A continuation request afterwards is a literal ack, must stay visible.
	h.feedReceived(t, "+ Ready for literal data\r\n")

	frames := sink.get()
	wantAuth := "T3 AUTHENTICATE PLAIN " + redacted
	if findFrame(frames, wantAuth) == nil {
		t.Fatalf("redacted AUTHENTICATE frame not found, got: %#v", frames)
	}
	if findFrame(frames, "T3 OK PLAIN authentication successful") == nil {
		t.Fatalf("tagged completion not found, got: %#v", frames)
	}
	if findFrame(frames, "+ Ready for literal data") == nil {
		t.Fatalf("post-auth continuation not visible, got: %#v", frames)
	}
}

func TestAuthenticateChallengeResponse(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideClient)

	h.writeChunks(t, []byte("T4 AUTHENTICATE SCRAM-SHA-256\r\n"), 10)
	h.feedReceived(t, "+ cj0xiA==\r\n")
	h.writeChunks(t, []byte("Yz1iaXpp\r\n"), 2) // bare SASL response
	h.feedReceived(t, "T4 NO Authentication failed\r\n")

	frames := sink.get()
	if len(frames) != 4 {
		t.Fatalf("got %d frames, want 4: %#v", len(frames), frames)
	}
	want := []recordedFrame{
		{dir: imap.TraceDirectionClient, frame: "T4 AUTHENTICATE SCRAM-SHA-256"},
		{dir: imap.TraceDirectionServer, frame: "+ " + redacted},
		{dir: imap.TraceDirectionClient, frame: redacted},
		{dir: imap.TraceDirectionServer, frame: "T4 NO Authentication failed"},
	}
	for i := range want {
		if frames[i] != want[i] {
			t.Errorf("frame %d = %#v, want %#v", i, frames[i], want[i])
		}
	}
}

func TestAuthenticateCancel(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideClient)

	h.writeChunks(t, []byte("T5 AUTHENTICATE PLAIN\r\n"), 10)
	h.feedReceived(t, "+ \r\n")
	h.writeChunks(t, []byte("*\r\n"), 1) // client cancellation
	h.feedReceived(t, "T5 BAD AUTHENTICATE cancelled\r\n")

	frames := sink.get()
	for i, want := range []string{
		"T5 AUTHENTICATE PLAIN",
		"+ " + redacted,
		redacted,
		"T5 BAD AUTHENTICATE cancelled",
	} {
		if frames[i].frame != want {
			t.Errorf("frame %d = %q, want %q", i, frames[i].frame, want)
		}
	}
}

func TestMultipleFramesInOneChunk(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideClient)

	// Pipelined commands delivered in a single write.
	h.writeChunks(t, []byte("T1 NOOP\r\nT2 LOGIN a b\r\nT3 LOGOUT\r\n"), 1000)

	frames := sink.get()
	if len(frames) != 3 {
		t.Fatalf("got %d frames, want 3: %#v", len(frames), frames)
	}
	if frames[1].frame != "T2 LOGIN "+redacted+" "+redacted {
		t.Errorf("LOGIN frame = %q", frames[1].frame)
	}
}

func TestServerSideDirectionMapping(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideServer)

	// On a server, reads are client frames and writes are server frames.
	h.feedReceived(t, "T1 LOGIN \"a\" \"b\"\r\n")
	h.writeChunks(t, []byte("* OK ready\r\nT1 OK Logged in\r\n"), 5)

	frames := sink.get()
	if len(frames) != 3 {
		t.Fatalf("got %d frames: %#v", len(frames), frames)
	}
	if frames[0].dir != imap.TraceDirectionClient || frames[0].frame != "T1 LOGIN "+redacted+" "+redacted {
		t.Errorf("frame 0 = %#v", frames[0])
	}
	if frames[1].dir != imap.TraceDirectionServer || frames[1].frame != "* OK ready" {
		t.Errorf("frame 1 = %#v", frames[1])
	}
}

func TestConcurrentFrames(t *testing.T) {
	h, sink := newHarness(imapwire.ConnSideClient)

	const n = 200
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			h.rw.Write([]byte("T1 NOOP\r\n"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			h.recvBuf.WriteString("* 1 EXISTS\r\n")
			p := make([]byte, len("* 1 EXISTS\r\n"))
			io.ReadFull(h.rw, p)
		}
	}()
	wg.Wait()

	frames := sink.get()
	if len(frames) != 2*n {
		t.Fatalf("got %d frames, want %d", len(frames), 2*n)
	}
	for _, f := range frames {
		// Frames must be complete and never contain line separators.
		if strings.ContainsAny(f.frame, "\r\n") {
			t.Fatalf("interleaved/incomplete frame: %q", f.frame)
		}
	}
}

// A panicking sink must not propagate to the connection.
type panickingSink struct{}

func (panickingSink) Trace(imap.TraceDirection, string) { panic("boom") }

func TestSinkPanicDoesNotBreakConnection(t *testing.T) {
	tr := New(panickingSink{}, imapwire.ConnSideClient)
	buf := new(bytes.Buffer)
	rw := tr.Wrap(struct {
		io.Reader
		io.Writer
	}{
		Reader: bytes.NewBufferString("* OK ready\r\n"),
		Writer: buf,
	})

	if _, err := rw.Write([]byte("T1 NOOP\r\n")); err != nil {
		t.Fatalf("Write() = %v", err)
	}
	if got := buf.String(); got != "T1 NOOP\r\n" {
		t.Fatalf("writer data = %q", got)
	}
	p := make([]byte, 100)
	n, err := rw.Read(p)
	if err != nil && err != io.EOF {
		t.Fatalf("Read() = %v", err)
	}
	if string(p[:n]) != "* OK ready\r\n" {
		t.Fatalf("reader data = %q", p[:n])
	}
}
