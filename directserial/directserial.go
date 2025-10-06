package directserial

import (
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"go.uber.org/zap"
)

type directSerial struct {
	transport base.Stream // usually tcp
	isopen    bool

	logger *zap.SugaredLogger
}

func (r *directSerial) logf(format string, v ...any) {
	if r.logger != nil {
		r.logger.Infof(format, v...)
	}
}

// Close implements SerialStream.
func (r *directSerial) Close() error {
	return nil // just do nothing, yes, bad semantic, should be renamed
}

// Disconnect implements SerialStream.
func (r *directSerial) Disconnect() error {
	r.isopen = false
	return r.transport.Disconnect()
}

// GetRxTxBytes implements SerialStream.
func (r *directSerial) GetRxTxBytes() (int64, int64) {
	return r.transport.GetRxTxBytes()
}

// Open implements SerialStream.
func (r *directSerial) Open() error {
	if r.isopen {
		return nil
	}

	if err := r.transport.Open(); err != nil {
		return err
	}

	r.isopen = true
	return nil
}

// Read implements SerialStream.
func (r *directSerial) Read(p []byte) (n int, err error) {
	if !r.isopen {
		return 0, base.ErrNotOpened
	}

	return r.transport.Read(p)
}

func (r *directSerial) SetTimeout(t time.Duration) {
	r.transport.SetTimeout(t)
}

// SetDeadline implements SerialStream.
func (r *directSerial) SetDeadline(t time.Time) {
	r.transport.SetDeadline(t)
}

// SetLogger implements SerialStream.
func (r *directSerial) SetLogger(logger *zap.SugaredLogger) {
	r.logger = logger
	r.transport.SetLogger(logger)
}

// SetMaxReceivedBytes implements SerialStream.
func (r *directSerial) SetMaxReceivedBytes(m int64) {
	r.transport.SetMaxReceivedBytes(m)
}

func (r *directSerial) SetDTR(dtr bool) error {
	if !r.isopen {
		return base.ErrNotOpened
	}

	r.logf("SetDTR: %v (ignoring)", dtr)
	return nil // just ignore that
}

// SetFlowControl implements SerialStream.
func (r *directSerial) SetFlowControl(flowControl base.SerialFlowControl) error {
	if !r.isopen {
		return base.ErrNotOpened
	}

	r.logf("SetFlowControl: %v (ignoring)", flowControl)
	return nil // just ignore that
}

// SetSpeed implements SerialStream.
func (r *directSerial) SetSpeed(baudRate int, dataBits base.SerialDataBits, parity base.SerialParity, stopBits base.SerialStopBits) error {
	if !r.isopen {
		return base.ErrNotOpened
	}

	r.logf("SetSpeed: %d,%v,%v,%v (ignoring)", baudRate, dataBits, parity, stopBits)
	return nil // just ignore that
}

// Write implements SerialStream.
func (r *directSerial) Write(src []byte) error {
	if !r.isopen {
		return base.ErrNotOpened
	}

	return r.transport.Write(src)
}

func New(t base.Stream) base.SerialStream {
	return &directSerial{
		transport: t,
		isopen:    false,
	}
}
