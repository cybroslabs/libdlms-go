package tcp

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
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
			t.logf("Connect to %s failed: %v", address, err)

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

func (t *tcp) IsOpen() bool {
	return t.connected
}

func (t *tcp) SetMaxReceivedBytes(m int64) {
	t.currentincoming = 0
	t.maxincoming = m
}

func (t *tcp) SetDeadline(d time.Time) {
	t.deadline = d
}

func (t *tcp) SetLogger(logger *zap.SugaredLogger) {
	t.logger = logger
}

func (t *tcp) setcommdeadline() {
	cd := time.Now().Add(t.timeout)
	if !t.deadline.IsZero() {
		_ = t.conn.SetDeadline(cd)
	} else {
		if cd.Compare(t.deadline) < 0 {
			_ = t.conn.SetDeadline(cd)
		} else {
			_ = t.conn.SetDeadline(t.deadline)
		}
	}
}

func (t *tcp) Write(src []byte) error {
	if !t.connected {
		return fmt.Errorf("not connected")
	}

	for len(src) > 0 {
		t.setcommdeadline()
		n, err := t.conn.Write(src) // does that fulfill io.Writer interface so it returns not nil err even there is less written bytes?
		if err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
		t.totaloutgoing += int64(n)

		if t.logger != nil {
			t.logger.Debugf("TX (%s): %6d %s", t.hostname, n, encodeHexString(src[:n]))
		}

		src = src[n:]
	}

	return nil
}

func (t *tcp) Read(p []byte) (n int, err error) {
	if !t.connected {
		return 0, fmt.Errorf("not connected")
	}
	if len(p) == 0 {
		return 0, fmt.Errorf("nothing to read")
	}

	n = len(p)
	rem := t.read - t.offset
	if rem > 0 { // having something unread in the buffer
		if n > rem {
			n = rem
		}
		copy(p, t.buffer[t.offset:t.offset+n])
		t.offset += n
		return
	}

	t.setcommdeadline()
	rx, err := t.conn.Read(t.buffer)
	t.totalincoming += int64(rx)
	t.currentincoming += int64(rx)
	if t.maxincoming > 0 && t.currentincoming > t.maxincoming {
		return 0, fmt.Errorf("received more than allowed")
	}

	if rx > 0 {
		t.read = rx
		if n > rx {
			n = rx
		}
		copy(p, t.buffer[:n])
		t.offset = n

		if t.logger != nil {
			t.logger.Debugf("RX (%s): %6d %s", t.hostname, rx, encodeHexString(t.buffer[:rx]))
		}
	}

	if err != nil {
		return 0, err
	}
	if rx == 0 { // this is a bit questionable
		return 0, io.EOF
	}
	return
}

func encodeHexString(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}
