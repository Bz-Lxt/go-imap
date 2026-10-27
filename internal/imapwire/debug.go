package imapwire

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"sync"
)

// NewDebugTracer creates a debug tracer writing sanitized IMAP frames to w.
//
// If w is nil, nil is returned.
//
// The tracer is passive: it never alters the exchanged data and errors
// returned by w are ignored, so tracing cannot corrupt or terminate the
// connection. A single tracer may be reused across STARTTLS upgrades via
// DebugTracer.Wrap, so that the trace spans the cleartext and encrypted
// phases of a connection without recording TLS handshake or ciphertext
// bytes.
func NewDebugTracer(w io.Writer, side ConnSide) *DebugTracer {
	if w == nil {
		return nil
	}
	t := &DebugTracer{w: w}
	switch side {
	case ConnSideClient:
		t.send = &debugStream{tracer: t, prefix: "C: ", request: true}
		t.recv = &debugStream{tracer: t, prefix: "S: ", request: false}
	case ConnSideServer:
		t.send = &debugStream{tracer: t, prefix: "S: ", request: false}
		t.recv = &debugStream{tracer: t, prefix: "C: ", request: true}
	default:
		panic("imapwire: invalid ConnSide")
	}
	return t
}

// DebugTracer records a sanitized, bidirectional trace of IMAP frames.
//
// Complete frames are reassembled before being written to the debug writer,
// so network fragmentation and concurrent sends/receives don't interleave
// trace output: each frame is emitted with a single, serialized Write.
//
// Sensitive payloads are never written to the debug writer:
//
//   - literal data is replaced by its declared length, e.g. "{42}";
//   - LOGIN arguments are replaced by "<redacted>";
//   - SASL initial responses, challenges and responses are redacted during
//     an AUTHENTICATE exchange.
//
// Each frame is written on a single line, prefixed with its direction:
// "C: " for client-to-server frames and "S: " for server-to-client frames.
type DebugTracer struct {
	w io.Writer

	// mu protects w, the send/recv stream state and the SASL state. All
	// tracing processing is done under it, making each emitted frame atomic
	// with respect to the other direction.
	mu sync.Mutex

	send *debugStream
	recv *debugStream

	// saslActive is true between an AUTHENTICATE command frame and the
	// matching tagged completion. saslTag is the command tag.
	saslActive bool
	saslTag    string
}

// Wrap returns an io.ReadWriter which traces the data exchanged via rw.
//
// Calling Wrap again (e.g. after a STARTTLS upgrade) reuses the same
// reassembly and SASL state.
func (t *DebugTracer) Wrap(rw io.ReadWriter) io.ReadWriter {
	if t == nil {
		return rw
	}
	return struct {
		io.Reader
		io.Writer
	}{
		Reader: &debugReader{r: rw, s: t.recv},
		Writer: &debugWriter{w: rw, s: t.send},
	}
}

// debugStream is the per-direction frame reassembler.
type debugStream struct {
	tracer *DebugTracer
	prefix string
	// request is true for the client-to-server (command) direction.
	request bool

	// line holds the in-progress frame, excluding CRLF and literal
	// payloads. skip is the number of remaining literal payload bytes to
	// discard before accumulating the rest of the frame.
	//
	// literalMark is the index at which bytes appended after a literal
	// payload begin: literal markers below it belong to a payload already
	// consumed and must not be detected again.
	line        []byte
	skip        int64
	literalMark int
}

// consume feeds a chunk of wire data to the reassembler. It must not retain
// p: interesting bytes are copied into the stream buffer, literal data is
// only counted.
func (s *debugStream) consume(p []byte) {
	t := s.tracer
	t.mu.Lock()
	defer t.mu.Unlock()

	for len(p) > 0 {
		if s.skip > 0 {
			n := int64(len(p))
			if n > s.skip {
				n = s.skip
			}
			p = p[n:]
			s.skip -= n
			if s.skip > 0 {
				return
			}
			continue
		}

		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			s.line = append(s.line, p...)
			return
		}
		s.line = append(s.line, p[:i]...)
		p = p[i+1:]

		// Be liberal: accept a lone LF, strip a trailing CR.
		if n := len(s.line); n > 0 && s.line[n-1] == '\r' {
			s.line = s.line[:n-1]
		}

		if size, ok := parseLiteralSuffix(s.line, s.literalMark); ok {
			// Keep the "{N}" marker in the output, discard exactly size
			// payload bytes, then keep accumulating the same frame.
			s.literalMark = len(s.line)
			s.skip = size
			continue
		}

		s.emitFrame()
		s.line = s.line[:0]
		s.literalMark = 0
	}
}

// emitFrame sanitizes and writes the completed frame. The caller holds
// tracer.mu.
func (s *debugStream) emitFrame() {
	line := s.line
	t := s.tracer

	if s.request {
		if tag, cmd, rest, ok := parseCommand(line); ok {
			switch cmd {
			case "LOGIN":
				line = []byte(tag + " LOGIN <redacted>")
			case "AUTHENTICATE":
				masked := tag + " AUTHENTICATE"
				if mech, args, _ := splitField(rest); mech != "" {
					masked += " " + mech
					if len(args) > 0 {
						masked += " <redacted>"
					}
				}
				line = []byte(masked)
				t.saslActive = true
				t.saslTag = tag
			}
		} else if t.saslActive && len(bytes.TrimSpace(line)) > 0 && !bytes.Equal(bytes.TrimSpace(line), []byte("*")) {
			// A bare line during an AUTHENTICATE exchange is a SASL
			// response ("*" is a cancellation request).
			line = []byte("<SASL response redacted>")
		}
	} else if t.saslActive {
		if len(line) > 0 && line[0] == '+' {
			// A continuation request carrying text is a SASL challenge;
			// an empty one just requests an initial response.
			if len(bytes.TrimSpace(line)) > 1 {
				line = []byte("+ <redacted>")
			}
		} else if tag, ok := firstField(line); ok && tag == t.saslTag {
			// Tagged completion of the AUTHENTICATE command.
			t.saslActive = false
			t.saslTag = ""
		}
	}

	buf := make([]byte, 0, len(s.prefix)+len(line)+1)
	buf = append(buf, s.prefix...)
	buf = append(buf, line...)
	buf = append(buf, '\n')
	// Best-effort: a debug write failure must never affect the connection.
	_, _ = t.w.Write(buf)
}

// parseCommand splits a command frame into tag, command name (uppercased)
// and the rest of the line.
func parseCommand(line []byte) (tag, cmd string, rest []byte, ok bool) {
	tag, after, ok := splitField(line)
	if !ok {
		return "", "", nil, false
	}
	name, rest, _ := splitField(after)
	if name == "" {
		return "", "", nil, false
	}
	return tag, strings.ToUpper(name), rest, true
}

// splitField splits b at the first space. The returned rest keeps its
// original contents.
func splitField(b []byte) (field string, rest []byte, ok bool) {
	i := bytes.IndexByte(b, ' ')
	if i < 0 {
		if len(b) == 0 {
			return "", nil, false
		}
		return string(b), nil, true
	}
	if i == 0 {
		return "", nil, false
	}
	return string(b[:i]), b[i+1:], true
}

// firstField returns the first space-delimited token of b.
func firstField(b []byte) (string, bool) {
	field, _, ok := splitField(b)
	return field, ok
}

// parseLiteralSuffix reports whether line ends with a literal prefix:
//
//	"{" ["~"] 1*DIGIT ["+"] "}"
//
// The declared literal size is returned. minStart is the index at which
// bytes following an already-consumed literal begin, preventing a marker
// retained in the line buffer from being detected again. Literal payloads
// may contain any byte (including CRLF), and are skipped by size rather
// than parsed.
func parseLiteralSuffix(line []byte, minStart int) (int64, bool) {
	end := len(line)
	if end == 0 || line[end-1] != '}' {
		return 0, false
	}

	i := end - 2
	if i >= 0 && line[i] == '+' { // non-synchronizing literal
		i--
	}

	digitsEnd := i + 1
	for i >= 0 && line[i] >= '0' && line[i] <= '9' {
		i--
	}
	digitsStart := i + 1
	if digitsStart == digitsEnd {
		return 0, false
	}

	if i >= 0 && line[i] == '~' { // literal8
		i--
	}
	if i < minStart || line[i] != '{' {
		return 0, false
	}

	size, err := strconv.ParseInt(string(line[digitsStart:digitsEnd]), 10, 64)
	if err != nil || size < 0 {
		return 0, false
	}
	return size, true
}

type debugReader struct {
	r io.Reader
	s *debugStream
}

func (dr *debugReader) Read(p []byte) (int, error) {
	n, err := dr.r.Read(p)
	if n > 0 {
		dr.s.consume(p[:n])
	}
	return n, err
}

type debugWriter struct {
	w io.Writer
	s *debugStream
}

func (dw *debugWriter) Write(p []byte) (int, error) {
	n, err := dw.w.Write(p)
	if n > 0 {
		dw.s.consume(p[:n])
	}
	return n, err
}
