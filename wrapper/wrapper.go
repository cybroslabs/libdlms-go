// Package wrapper implements the DLMS Wrapper protocol for TCP/IP transport.
//
// The Wrapper protocol provides a simple framing mechanism for DLMS messages over TCP/IP,
// as an alternative to HDLC. It's typically used with direct TCP connections to meters.
//
// The wrapper adds a 8-byte header containing:
//   - Version (2 bytes): Always 0x0001
//   - Source WPORT (2 bytes): Logical address of sender
//   - Destination WPORT (2 bytes): Logical address of receiver
//   - Length (2 bytes): Payload length
//
// Usage:
//
//	wrapperTransport, err := wrapper.New(tcpTransport, 1, 1)
//	err = wrapperTransport.Open()
package wrapper

import (
	"fmt"
	"io"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"go.uber.org/zap"
)

type wrapper struct {
	transport   base.Stream
	logger      *zap.SugaredLogger
	source      uint16
	destination uint16
	buffer      []byte // send buffer and header buffer
	remaining   int
	expresp     bool
	towrite     int
}

func (w *wrapper) logf(format string, v ...any) {
	if w.logger != nil {
		w.logger.Infof(format, v...)
	}
}

// New creates a new DLMS wrapper protocol layer around the provided transport stream.
// The source and destination are WPORT addresses used in the wrapper header.
func New(transport base.Stream, source uint16, destination uint16) (base.Stream, error) {
	return &wrapper{
		transport:   transport,
		logger:      nil,
		source:      source,
		destination: destination,
		buffer:      make([]byte, 2048),
		remaining:   0,
		expresp:     false,
		towrite:     0,
	}, nil
}

func (w *wrapper) Close() error {
	return w.transport.Close()
}

func (w *wrapper) Disconnect() error {
	return w.transport.Disconnect()
}

func (w *wrapper) Open() error {
	w.logf("Opening wrapper with source %d and destination %d", w.source, w.destination)
	return w.transport.Open()
}

func (w *wrapper) SetMaxReceivedBytes(m int64) {
	w.transport.SetMaxReceivedBytes(m)
}

func (w *wrapper) SetTimeout(to time.Duration) {
	w.transport.SetTimeout(to)
}

func (w *wrapper) SetDeadline(t time.Time) {
	w.transport.SetDeadline(t)
}

func (w *wrapper) SetLogger(logger *zap.SugaredLogger) {
	w.logger = logger
	w.transport.SetLogger(logger)
}

func (w *wrapper) Write(src []byte) error {
	if len(src) == 0 {
		return nil
	}
	if w.towrite+len(src) > 65535+8 {
		return fmt.Errorf("packet too big: size=%d max=%d", w.towrite+len(src), 65535+8)
	}
	// readout remaining bytes?
	for w.remaining > 0 {
		n, err := w.transport.Read(w.buffer)
		w.remaining -= n
		if err != nil {
			return err
		}
		if n == 0 { // that shouldnt happen
			return fmt.Errorf("no data read")
		}
	}

	if w.towrite == 0 {
		w.buffer[0] = 0
		w.buffer[1] = 1
		w.buffer[2] = byte(w.source >> 8)
		w.buffer[3] = byte(w.source)
		w.buffer[4] = byte(w.destination >> 8)
		w.buffer[5] = byte(w.destination)
		w.towrite = 8 // make space for header for sure
	}

	if w.towrite+len(src) > len(w.buffer) {
		tmp := make([]byte, w.towrite+len(src))
		copy(tmp, w.buffer[:w.towrite])
		w.buffer = tmp
	}

	copy(w.buffer[w.towrite:], src)
	w.towrite += len(src)
	w.expresp = true
	return nil
}

func (w *wrapper) flush() error {
	if w.towrite == 0 {
		return fmt.Errorf("there is nothing to flush, this shouldnt happen")
	}

	w.buffer[6] = byte((w.towrite - 8) >> 8)
	w.buffer[7] = byte(w.towrite - 8)
	err := w.transport.Write(w.buffer[:w.towrite])
	if err != nil {
		return err
	}

	w.towrite = 0
	return nil
}

func (w *wrapper) Read(p []byte) (n int, err error) {
	if w.expresp {
		err = w.flush()
		if err != nil {
			return
		}

		_, err = io.ReadFull(w.transport, w.buffer[:8])
		if err != nil {
			return
		}

		// parse and check header, copy the possible rest to buffer and receive the rest of the packet
		if w.buffer[0] != 0 || w.buffer[1] != 1 {
			return 0, fmt.Errorf("invalid header version")
		}
		rsrc := uint16(w.buffer[2])<<8 | uint16(w.buffer[3])
		rdest := uint16(w.buffer[4])<<8 | uint16(w.buffer[5])
		if rsrc != w.destination || rdest != w.source {
			return 0, fmt.Errorf("invalid source or destination")
		}

		w.remaining = int(uint16(w.buffer[6])<<8 | uint16(w.buffer[7]))
		w.expresp = false
	}

	n = len(p)
	if n == 0 {
		return 0, base.ErrNothingToRead
	}
	if w.remaining == 0 {
		return 0, io.EOF
	}
	if n > w.remaining {
		n = w.remaining
	}
	n, err = w.transport.Read(p[:n])
	w.remaining -= n
	return
}

func (w *wrapper) GetRxTxBytes() (int64, int64) {
	return w.transport.GetRxTxBytes()
}
