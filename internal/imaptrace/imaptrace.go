// Package imaptrace implements a passive, redacting IMAP protocol tracer.
//
// It taps the byte stream of an IMAP connection, reassembles complete
// protocol frames (reassembling network fragments and skipping over literal
// payloads), redacts sensitive data (LOGIN credentials, SASL exchanges and
// message contents) and reports each frame to an imap.Tracer sink.
//
// The tracer is strictly passive: connection data is forwarded unchanged and
// sink failures cannot affect the connection.
package imaptrace

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/internal/imapwire"
)

// maxFrameSize bounds the amount of buffered data for a single frame. If a
// frame exceeds this size (e.g. because the stream is desynchronized), the
// partial frame is discarded and the stream resynchronizes on the next LF.
const maxFrameSize = 1 << 20

const redacted = "<redacted>"

// Tracer reassembles and redacts IMAP protocol frames.
//
// A single Tracer must be used for the whole lifetime of a connection,
// including across STARTTLS upgrades.
type Tracer struct {
	mu     sync.Mutex
	sink   imap.Tracer
	readD  imap.TraceDirection
	writeD imap.TraceDirection

	client stream // client -> server
	server stream // server -> client

	// saslTag is the tag of the AUTHENTICATE command currently being
	// exchanged, or empty if no SASL exchange is in progress. It is shared
	// between the two directions because a SASL exchange involves frames on
	// both sides.
	saslTag string
}

// stream is the per-direction frame reassembler.
type stream struct {
	buf     bytes.Buffer
	literal int64 // remaining literal payload bytes to skip
}

// New creates a new Tracer for a connection on the given local side.
func New(sink imap.Tracer, side imapwire.ConnSide) *Tracer {
	t := &Tracer{sink: sink}
	switch side {
	case imapwire.ConnSideClient:
		t.readD = imap.TraceDirectionServer
		t.writeD = imap.TraceDirectionClient
	case imapwire.ConnSideServer:
		t.readD = imap.TraceDirectionClient
		t.writeD = imap.TraceDirectionServer
	}
	return t
}

// Wrap installs the tracer around rw.
//
// The returned ReadWriter forwards all data unchanged.
func (t *Tracer) Wrap(rw io.ReadWriter) io.ReadWriter {
	if t == nil {
		return rw
	}
	return struct {
		io.Reader
		io.Writer
	}{
		Reader: &tracedReader{r: rw, t: t, dir: t.readD},
		Writer: &tracedWriter{w: rw, t: t, dir: t.writeD},
	}
}

// Reset discards partially reassembled frames.
//
// It must be called when the underlying transport is replaced (e.g. during a
// STARTTLS upgrade), which always happens on a frame boundary.
func (t *Tracer) Reset() {
	t.mu.Lock()
	t.client.buf.Reset()
	t.client.literal = 0
	t.server.buf.Reset()
	t.server.literal = 0
	t.mu.Unlock()
}

type tracedReader struct {
	r   io.Reader
	t   *Tracer
	dir imap.TraceDirection
}

func (tr *tracedReader) Read(p []byte) (int, error) {
	n, err := tr.r.Read(p)
	if n > 0 {
		tr.t.feed(tr.dir, p[:n])
	}
	return n, err
}

type tracedWriter struct {
	w   io.Writer
	t   *Tracer
	dir imap.TraceDirection
}

func (tw *tracedWriter) Write(p []byte) (int, error) {
	n, err := tw.w.Write(p)
	if n > 0 {
		tw.t.feed(tw.dir, p[:n])
	}
	return n, err
}

func (t *Tracer) streamFor(dir imap.TraceDirection) *stream {
	if dir == imap.TraceDirectionClient {
		return &t.client
	}
	return &t.server
}

// feed consumes a chunk of wire data for a direction.
func (t *Tracer) feed(dir imap.TraceDirection, p []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	s := t.streamFor(dir)
	for _, ch := range p {
		if s.literal > 0 {
			s.literal--
			continue
		}

		s.buf.WriteByte(ch)
		if ch != '\n' {
			if s.buf.Len() > maxFrameSize {
				// Resynchronize at the next LF.
				s.buf.Reset()
			}
			continue
		}

		if size, hdrLen, ok := parseLiteralHeader(s.buf.Bytes()); ok {
			b := s.buf.Bytes()
			s.buf.Truncate(len(b) - hdrLen)
			// Internal placeholder: NUL cannot appear in IMAP protocol
			// text, so the placeholder cannot be mistaken for another
			// literal header. It is rendered as "{size}" at emit time.
			s.buf.WriteByte(0)
			s.buf.WriteString(strconv.FormatInt(size, 10))
			s.buf.WriteByte('}')
			s.literal = size
		} else {
			frame := s.buf.Bytes()
			frame = bytes.TrimSuffix(frame, []byte("\n"))
			frame = bytes.TrimSuffix(frame, []byte("\r"))
			t.emit(dir, frame)
			s.buf.Reset()
		}
	}
}

// parseLiteralHeader checks whether b ends with a literal header
// ("{" ["~"] 1*DIGIT ["+"] "}" CR LF or LF). It returns the declared literal
// size and the header length in bytes.
func parseLiteralHeader(b []byte) (size int64, hdrLen int, ok bool) {
	i := len(b) - 2 // index of the byte before '\n'
	if i < 0 {
		return 0, 0, false
	}
	if b[i] == '\r' { // CR is optional, be liberal in what we accept
		i--
	}
	if i < 0 || b[i] != '}' {
		return 0, 0, false
	}
	i--
	if i >= 0 && b[i] == '+' {
		i--
	}
	digitsEnd := i + 1
	for i >= 0 && b[i] >= '0' && b[i] <= '9' {
		i--
	}
	digitsStart := i + 1
	if digitsStart == digitsEnd {
		return 0, 0, false
	}
	if i >= 0 && b[i] == '~' {
		i--
	}
	if i < 0 || b[i] != '{' {
		return 0, 0, false
	}
	size, err := strconv.ParseInt(string(b[digitsStart:digitsEnd]), 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return size, len(b) - i, true
}

func (t *Tracer) emit(dir imap.TraceDirection, frame []byte) {
	// A buggy sink (or redaction bug) must not be able to break the
	// connection.
	defer func() {
		recover()
	}()

	// Render literal placeholders as "{size}".
	frame = bytes.ReplaceAll(frame, []byte{0}, []byte{'{'})
	frame = t.redact(dir, frame)

	t.sink.Trace(dir, string(frame))
}

// redact returns a copy of frame with sensitive data masked.
func (t *Tracer) redact(dir imap.TraceDirection, frame []byte) []byte {
	toks := tokenize(frame)

	if t.saslTag != "" && len(toks) > 0 {
		first := string(frame[toks[0][0]:toks[0][1]])
		if first == t.saslTag {
			// Tagged response: the SASL exchange is complete.
			t.saslTag = ""
			return frame
		}
		if dir == imap.TraceDirectionServer {
			if first == "+" {
				// SASL server challenge.
				return []byte("+ " + redacted)
			}
			return frame
		}
		// A client-to-server frame during a SASL exchange is the SASL
		// response (or a "*" cancellation).
		return []byte(redacted)
	}

	if len(toks) < 2 {
		return frame
	}

	tag := string(frame[toks[0][0]:toks[0][1]])
	cmd := strings.ToUpper(string(frame[toks[1][0]:toks[1][1]]))

	switch cmd {
	case "LOGIN":
		// Mask the username and password, whatever their encoding.
		var idxs []int
		for _, i := range []int{2, 3} {
			if i < len(toks) {
				idxs = append(idxs, i)
			}
		}
		if len(idxs) == 0 {
			// Malformed frame: mask the rest of the line.
			return replaceTail(frame, toks[1][1])
		}
		return replaceTokens(frame, toks, idxs)
	case "AUTHENTICATE":
		t.saslTag = tag
		// Keep the mechanism visible, mask the SASL initial response.
		if len(toks) >= 4 {
			return replaceTail(frame, toks[3][0])
		}
		return frame
	default:
		return frame
	}
}

// tokenize splits a frame into whitespace-separated tokens, honoring quoted
// strings.
func tokenize(b []byte) [][2]int {
	var toks [][2]int
	i := 0
	for i < len(b) {
		for i < len(b) && b[i] == ' ' {
			i++
		}
		if i == len(b) {
			break
		}
		start := i
		if b[i] == '"' {
			i++
			for i < len(b) {
				if b[i] == '\\' {
					i += 2
					continue
				}
				if b[i] == '"' {
					i++
					break
				}
				i++
			}
		} else {
			for i < len(b) && b[i] != ' ' {
				i++
			}
		}
		toks = append(toks, [2]int{start, i})
	}
	return toks
}

// replaceTokens replaces the given token indexes with a redaction marker.
func replaceTokens(frame []byte, toks [][2]int, idxs []int) []byte {
	var out bytes.Buffer
	pos := 0
	for _, idx := range idxs {
		start, end := toks[idx][0], toks[idx][1]
		out.Write(frame[pos:start])
		out.WriteString(redacted)
		pos = end
	}
	out.Write(frame[pos:])
	return out.Bytes()
}

// replaceTail replaces everything from offset to the end of the frame with a
// redaction marker. A single separating space is preserved.
func replaceTail(frame []byte, offset int) []byte {
	prefix := bytes.TrimRight(frame[:offset], " ")
	out := make([]byte, 0, len(prefix)+1+len(redacted))
	out = append(out, prefix...)
	out = append(out, ' ')
	out = append(out, redacted...)
	return out
}
