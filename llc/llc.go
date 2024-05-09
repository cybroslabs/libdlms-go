package llc

import (
	"fmt"
	"io"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"go.uber.org/zap"
)

type llc struct {
	transport base.Stream
	logger    *zap.SugaredLogger
	header    []byte
	state     int // 0 - start, 1 - writting, 2 - reading
}

// Close implements base.Stream.
func (l *llc) Close() error {
	return l.transport.Close()
}

// Disconnect implements base.Stream.
func (l *llc) Disconnect() error {
	return l.transport.Disconnect()
}

// IsOpen implements base.Stream.
func (l *llc) IsOpen() bool {
	return l.transport.IsOpen()
}

// Open implements base.Stream.
func (l *llc) Open() error {
	return l.transport.Open()
}

// Receive implements base.Stream.
func (l *llc) Read(p []byte) (n int, err error) {
	if l.state == 2 {
		return l.transport.Read(p)
	}
	l.state = 2
	_, err = io.ReadFull(l.transport, l.header)
	if err != nil {
		return
	}
	if l.header[0] != 0xe6 || l.header[1] != 0xe7 || l.header[2] != 0 {
		return 0, fmt.Errorf("invalid LLC received header")
	}
	return l.transport.Read(p)
}

// Send implements base.Stream.
func (l *llc) Write(src []byte) error { // always write everything
	if l.state == 1 {
		return l.transport.Write(src)
	}
	l.state = 1
	l.header[0] = 0xe6
	l.header[1] = 0xe6
	l.header[2] = 0x00
	err := l.transport.Write(l.header)
	if err != nil {
		return err
	}
	return l.transport.Write(src)
}

func (l *llc) SetMaxReceivedBytes(m int64) {
	l.transport.SetMaxReceivedBytes(m)
}

func (l *llc) SetDeadline(t time.Time) {
	l.transport.SetDeadline(t)
}

// SetLogger implements base.Stream.
func (l *llc) SetLogger(logger *zap.SugaredLogger) {
	l.logger = logger
	l.transport.SetLogger(logger)
}

func (l *llc) GetRxTxBytes() (int64, int64) {
	return l.transport.GetRxTxBytes()
}

func New(transport base.Stream) base.Stream {
	return &llc{
		transport: transport,
		logger:    nil,
		header:    make([]byte, 3), // buffer jak hovado
		state:     0,
	}
}
