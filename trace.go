package imap

import (
	"fmt"
	"io"
	"sync"
)

// TraceDirection is the direction of a traced IMAP protocol frame.
type TraceDirection int

const (
	// TraceDirectionClient represents a frame sent by the client.
	TraceDirectionClient TraceDirection = 1 + iota
	// TraceDirectionServer represents a frame sent by the server.
	TraceDirectionServer
)

// Tracer is a secure, redacting IMAP protocol tracer.
//
// A tracer receives complete IMAP protocol frames, one call per frame.
// Network fragments are reassembled before being reported, and frames from
// both directions are delivered serially so they cannot interleave. Command
// tags are kept visible and literal payloads are replaced by a placeholder
// containing their size. LOGIN credentials, SASL exchanges and message
// contents are redacted.
//
// A tracer is passive: it never alters the connection data and must not
// block. Implementations must be safe for concurrent use.
type Tracer interface {
	// Trace reports a single complete protocol frame. The frame does not
	// contain a trailing CRLF.
	Trace(dir TraceDirection, frame string)
}

// NewTracer creates a Tracer which writes one human-readable line per frame
// to w.
//
// Each line starts with the direction ("C" for client, "S" for server) and a
// connection-wide monotonically increasing sequence number, for instance:
//
//	C 0001 T1 STARTTLS
//	S 0002 T1 OK Begin TLS negotiation now
//	C 0003 T2 LOGIN <redacted> <redacted>
//	C 0004 T3 APPEND INBOX {1234}
//
// Writes to w are serialized, so the returned tracer is safe for concurrent
// use.
func NewTracer(w io.Writer) Tracer {
	return &writeTracer{w: w}
}

type writeTracer struct {
	w   io.Writer
	mu  sync.Mutex
	seq uint64
}

func (t *writeTracer) Trace(dir TraceDirection, frame string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.seq++

	var ch byte
	switch dir {
	case TraceDirectionClient:
		ch = 'C'
	case TraceDirectionServer:
		ch = 'S'
	default:
		ch = '?'
	}

	fmt.Fprintf(t.w, "%c %04d %s\n", ch, t.seq, frame)
}
