package tcp

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"go.uber.org/zap"
)

type tcp struct {
	hostname        string
	port            int
	logger          *zap.SugaredLogger
	connected       bool
	timeout         time.Duration
	conn            net.Conn
	offset          int
	read            int
	buffer          []byte
	deadline        time.Time
	totalincoming   int64
	totaloutgoing   int64
	currentincoming int64
	maxincoming     int64
	inerror         error
}

func New(hostname string, port int, timeout time.Duration) base.Stream {
	return &tcp{
		hostname:        hostname,
		port:            port,
		logger:          nil,
		connected:       false,
		timeout:         timeout,
		conn:            nil,
		offset:          0,
		read:            0,
		buffer:          make([]byte, 2048),
		deadline:        time.Time{},
		totalincoming:   0,
		totaloutgoing:   0,
		currentincoming: 0,
		maxincoming:     0,
	}
}

func (w *tcp) logf(format string, v ...any) {
	if w.logger != nil {
		w.logger.Infof(format, v...)
	}
}

func (t *tcp) Close() error {
	return nil // do nothing as there is no association, this is usual behaviour
}

func (t *tcp) Open() error {
	if !t.connected {
		address := net.JoinHostPort(t.hostname, strconv.Itoa(t.port))

		conn, err := net.DialTimeout("tcp", address, t.timeout)
		if err != nil {
			t.logf("Connect to %s failed: %v", address, err.Error())

			return fmt.Errorf("connect failed: %w", err)
		}

		t.logf("Connected to %s", address)

		t.conn = conn
		t.connected = true
	}
	return nil
}

func (t *tcp) Disconnect() error {
	if t.connected {
		t.connected = false

		if t.conn != nil {
			_ = t.conn.Close()
			t.conn = nil
		}

		t.logf("Disconnected from %s", t.hostname)
		t.logf("Total bytes incoming: %v, outgoing: %v", t.totalincoming, t.totaloutgoing)
	}

	return nil
}

func (t *tcp) SetMaxReceivedBytes(m int64) {
	t.currentincoming = 0
	t.maxincoming = m
}

func (t *tcp) SetTimeout(to time.Duration) {
	t.timeout = to
	t.setcommdeadline()
}

func (t *tcp) SetDeadline(d time.Time) {
	t.deadline = d
	t.setcommdeadline()
}

func (t *tcp) SetLogger(logger *zap.SugaredLogger) {
	t.logger = logger
}

func (t *tcp) setcommdeadline() { // yes, this is shit
	var zero time.Time
	if t.deadline.IsZero() {
		if t.timeout == 0 {
			_ = t.conn.SetDeadline(zero) // i dont have to call every time, but this simulates timeout
		}
		_ = t.conn.SetDeadline(time.Now().Add(t.timeout))
	} else {
		if t.timeout == 0 {
			_ = t.conn.SetDeadline(t.deadline)
		} else {
			cd := time.Now().Add(t.timeout)
			if cd.Before(t.deadline) {
				_ = t.conn.SetDeadline(cd)
			} else {
				_ = t.conn.SetDeadline(t.deadline)
			}
		}
	}
}

func (t *tcp) Write(src []byte) error {
	if !t.connected {
		return base.ErrNotOpened
	}

	for len(src) > 0 {
		t.setcommdeadline()
		n, err := t.conn.Write(src) // does that fulfill io.Writer interface so it returns not nil err even there is less written bytes?
		if err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
		t.totaloutgoing += int64(n)

		if t.logger != nil {
			t.logger.Debugf(base.LogHex("TX", src[:n]))
		}

		src = src[n:]
	}

	return nil
}

func (t *tcp) Read(p []byte) (int, error) {
	if !t.connected {
		return 0, base.ErrNotOpened
	}
	if len(p) == 0 {
		return 0, base.ErrNothingToRead
	}

	n := len(p)
	rem := t.read - t.offset
	if rem > 0 { // having something unread in the buffer
		if n > rem {
			n = rem
		}
		copy(p, t.buffer[t.offset:t.offset+n])
		t.offset += n
		return n, nil
	}
	if t.inerror != nil {
		err := t.inerror
		t.inerror = nil
		return 0, err
	}

	t.setcommdeadline()
	t.read, t.inerror = t.conn.Read(t.buffer)
	t.totalincoming += int64(t.read)
	t.currentincoming += int64(t.read)
	if t.maxincoming > 0 && t.currentincoming > t.maxincoming {
		return 0, fmt.Errorf("received more than allowed")
	}

	if t.read > 0 {
		if t.logger != nil {
			t.logger.Debugf(base.LogHex("RX", t.buffer[:t.read]))
		}

		t.offset = 0
		return t.Read(p)
	}

	if t.inerror != nil {
		err := t.inerror
		t.inerror = nil
		return 0, err
	}
	return 0, io.EOF // this is a bit questionable
}

func (t *tcp) GetRxTxBytes() (int64, int64) {
	return t.totalincoming, t.totaloutgoing
}
