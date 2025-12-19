package moxarealcom

import (
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"github.com/cybroslabs/libdlms-go/tcp"
	"go.uber.org/zap"
)

const (
	ASPP_CMD_PORT_INIT   = 0x2c
	ASPP_CMD_NOTIFY      = 0x26
	ASPP_CMD_WAIT_OQUEUE = 0x2f
	ASPP_CMD_TX_FIFO     = 0x30
	ASPP_CMD_XONXOFF     = 0x18
	ASPP_CMD_IOCTL       = 0x10
	ASPP_CMD_FLOWCTRL    = 0x11
	ASPP_CMD_LINECTRL    = 0x12
	ASPP_CMD_FLUSH       = 0x14
	ASPP_CMD_POLLING     = 0x27
	ASPP_CMD_ALIVE       = 0x28
)

type moxaRealCom struct {
	transport   base.Stream // usually tcp
	isopen      bool
	writebuffer []byte
	timeout     time.Duration

	cmdconn  net.Conn
	incoming atomic.Int64 // no limits are set here as main limit is at data transport layer
	outgoing atomic.Int64
	hostname string
	cmdport  int

	settings base.SerialStreamSettings

	logger *zap.SugaredLogger

	cmderr  atomic.Value
	cmdresp chan []byte
	cmdreq  chan byte
}

// Close implements base.SerialStream.
func (m *moxaRealCom) Close() error {
	return nil
}

// Disconnect implements base.SerialStream.
func (m *moxaRealCom) Disconnect() (err error) {
	if m.isopen {
		m.isopen = false
		err = m.transport.Disconnect()
		cerr := m.cmdconn.Close() // close that shit at all cost, so unblock some possible forever stuck read
		if err == nil {
			err = cerr
		}
		close(m.cmdreq)
	}
	return
}

func (w *moxaRealCom) logf(format string, v ...any) {
	if w.logger != nil {
		w.logger.Infof(format, v...)
	}
}

func (w *moxaRealCom) logd(format string, v ...any) {
	if w.logger != nil {
		w.logger.Debugf(format, v...)
	}
}

func (m *moxaRealCom) GetRxTxBytes() (int64, int64) {
	i, o := m.transport.GetRxTxBytes()
	return i + m.incoming.Load(), o + m.outgoing.Load()
}

func baudstobyte(b int) (byte, error) {
	switch b {
	case 300:
		return 0, nil
	case 600:
		return 1, nil
	case 1200:
		return 2, nil
	case 2400:
		return 3, nil
	case 4800:
		return 4, nil
	case 7200:
		return 5, nil
	case 9600:
		return 6, nil
	case 19200:
		return 7, nil
	case 38400:
		return 8, nil
	case 57600:
		return 9, nil
	case 115200:
		return 10, nil
	case 230400:
		return 11, nil
	case 460800:
		return 12, nil
	case 921600:
		return 13, nil
	case 150:
		return 14, nil
	case 134:
		return 15, nil
	case 110:
		return 16, nil
	case 75:
		return 17, nil
	case 50:
		return 18, nil
	}
	return 0, fmt.Errorf("unsupported baud rate %v", b)
}

func (m *moxaRealCom) modebyte() (b byte) {
	switch m.settings.DataBits {
	case base.Serial5DataBits:
	case base.Serial6DataBits:
		b |= 0x01
	case base.Serial7DataBits:
		b |= 0x02
	case base.Serial8DataBits:
		b |= 0x03
	}
	if m.settings.StopBits == base.SerialTwoStopBits {
		b |= 0x04
	}
	switch m.settings.Parity { // moxa sdk says odd: 0x08, even: 0x18, mark: 0x28, space: 0x38, code here is based on linux kernel driver
	case base.SerialNoParity:
	case base.SerialOddParity:
		b |= 0x10
	case base.SerialEvenParity:
		b |= 0x08
	case base.SerialMarkParity:
		b |= 0x18
	case base.SerialSpaceParity:
		b |= 0x20
	}
	return
}

func (m *moxaRealCom) Open() error { // first open cmd port and send the init
	var initcmd [10]byte
	if m.isopen {
		return nil
	}
	b, err := baudstobyte(m.settings.BaudRate)
	if err != nil {
		return err
	}

	var dataerr error
	var cmderr error
	var wg sync.WaitGroup
	address := net.JoinHostPort(m.hostname, strconv.Itoa(m.cmdport))
	wg.Go(func() {
		dataerr = m.transport.Open()
	})
	m.cmdconn, cmderr = net.DialTimeout("tcp", address, m.timeout)
	wg.Wait()
	if dataerr != nil {
		if m.cmdconn != nil {
			_ = m.cmdconn.Close()
		}
		return dataerr
	}
	if cmderr != nil {
		_ = m.transport.Disconnect()
		m.logf("Connect to %s failed: %v", address, cmderr)
		return fmt.Errorf("connect to command port failed: %w", cmderr)
	}

	initcmd[0] = ASPP_CMD_PORT_INIT
	initcmd[1] = 0x08 // 8 bytes here
	initcmd[2] = b
	initcmd[3] = m.modebyte()
	initcmd[4] = 1 // DTR set to 1
	initcmd[5] = 1 // RTS set to 1
	switch m.settings.FlowControl {
	case base.SerialNoFlowControl: // keep that zero
	case base.SerialSWFlowControl:
		initcmd[6] = 1 // set RTS to 1, need to check that
		initcmd[8] = 1 // ixon
		initcmd[9] = 1 // ixoff
	case base.SerialHWFlowControl:
		initcmd[6] = 1
		initcmd[7] = 1
	}

	m.cmdreq = make(chan byte, 1) // single outgoing command
	m.cmdresp = make(chan []byte)
	go m.commandhandler()

	resp, err := m.handlecommand(initcmd[:])
	if err != nil {
		_ = m.cmdconn.Close()
		close(m.cmdreq)
		_ = m.transport.Disconnect()
		return err
	}
	err = m.initResponse(resp)
	if err != nil {
		_ = m.cmdconn.Close()
		close(m.cmdreq)
		_ = m.transport.Disconnect()
		return err
	}

	m.isopen = true
	return nil
}

func (m *moxaRealCom) initResponse(resp []byte) error {
	if resp[1] != 3 { // length
		return fmt.Errorf("invalid init response second byte 0x%02x", resp[1])
	}
	return nil // not needed handle DSR CTS or DCD so just ignore those
}

func (m *moxaRealCom) commandhandler() {
	var expected byte // hopefully there is no zero command ;)
	var ok bool
	defer close(m.cmdresp)
	defer func() { // yes this is a bit overkill
		select {
		case <-m.cmdreq: // nonblocking readout
		default:
		}
	}()

	for {
		cmdbuff := make([]byte, 64) // only short commands? this is a bit risky, put that to the heap and send reference using channel
		// but make unknown commands error and stop the handler
		_, err := io.ReadFull(m.cmdconn, cmdbuff[:1])
		if err != nil {
			m.cmderr.Store(err)
			return
		}
		var ccmd []byte
		var wlen int
		switch cmdbuff[0] { // this is a bit crazy, log whole command after deciding according to first byte, undocumented piece of shit
		case ASPP_CMD_PORT_INIT:
			wlen = 5 // but usually the length is the second byte, damn that protocol
		case ASPP_CMD_NOTIFY, ASPP_CMD_WAIT_OQUEUE:
			wlen = 4
		case ASPP_CMD_TX_FIFO, ASPP_CMD_XONXOFF, ASPP_CMD_IOCTL, ASPP_CMD_FLOWCTRL, ASPP_CMD_LINECTRL, ASPP_CMD_FLUSH, ASPP_CMD_POLLING:
			wlen = 3
		default:
			m.logf("unknown command received: 0x%02x", cmdbuff[0]) // for now, consider that an error
			m.cmderr.Store(fmt.Errorf("unknown command received: 0x%02x", cmdbuff[0]))
			return
		}
		_, err = io.ReadFull(m.cmdconn, cmdbuff[1:wlen])
		if err != nil {
			m.cmderr.Store(err)
			return
		}
		ccmd = cmdbuff[:wlen]
		m.logd(base.LogHex("CMD RX", ccmd))
		m.incoming.Add(int64(len(ccmd)))

		if expected == 0 {
			select {
			case expected, ok = <-m.cmdreq:
				if !ok {
					m.cmderr.Store(fmt.Errorf("command handler closed"))
					return
				}
			default: // non blocking
			}
		}
		if ccmd[0] == expected {
			expected = 0
			select {
			case m.cmdresp <- ccmd:
			case <-m.cmdreq: // consider that a close, outside thing CANT send more than one command without reading or timeouting response
				m.cmderr.Store(fmt.Errorf("command handler closed"))
				return
			}
			continue
		}
		// handle unwanted notify command somehow here
		switch cmdbuff[0] {
		case ASPP_CMD_PORT_INIT:
			m.logf("strange, unwanted init command, ignored")
		case ASPP_CMD_POLLING:
			m.logf("polling received, sending alive answer")
			ccmd[0] = ASPP_CMD_ALIVE
			m.logd(base.LogHex("CMD TX", ccmd))
			_, err = m.cmdconn.Write(ccmd) // thread safe, so no lock here
			if err != nil {
				m.logf("unable to send alive response: %v", err)
				m.cmderr.Store(err)
				return
			}
			m.outgoing.Add(int64(len(ccmd)))
		case ASPP_CMD_NOTIFY:
			m.logf("process port notify command")
			if cmdbuff[1]&0x20 != 0 {
				m.logf("CTS changed to %v", cmdbuff[2]&0x10 != 0)
				m.logf("DSR changed to %v", cmdbuff[2]&0x20 != 0)
				m.logf("DCD changed to %v", cmdbuff[2]&0x80 != 0)
			}
		case ASPP_CMD_WAIT_OQUEUE, ASPP_CMD_TX_FIFO, ASPP_CMD_XONXOFF, ASPP_CMD_IOCTL, ASPP_CMD_FLOWCTRL, ASPP_CMD_LINECTRL, ASPP_CMD_FLUSH:
			m.logf("unwanted command response received: 0x%02x, ignored", cmdbuff[0])
		default:
			m.logf("unknown command received: 0x%02x, ignored", cmdbuff[0])
		}
	}
}

func (m *moxaRealCom) handlecommand(cmd []byte) ([]byte, error) {
	cerr := m.cmderr.Load()
	if cerr != nil {
		return nil, cerr.(error)
	}
	if len(cmd) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	m.cmdreq <- cmd[0]
	if m.timeout != 0 {
		_ = m.cmdconn.SetWriteDeadline(time.Now().Add(m.timeout))
	}
	m.logd(base.LogHex("CMD TX", cmd))
	_, err := m.cmdconn.Write(cmd)
	if err != nil {
		return nil, err
	}
	m.outgoing.Add(int64(len(cmd)))
	select {
	case resp, ok := <-m.cmdresp:
		if !ok {
			return nil, fmt.Errorf("command handler closed")
		}
		return resp, nil
	case <-time.After(m.timeout):
		return nil, fmt.Errorf("command timeout")
	}
}

func (m *moxaRealCom) handleOkCmd(cmd []byte) error {
	resp, err := m.handlecommand(cmd)
	if err != nil {
		_ = m.cmdconn.Close()
		close(m.cmdreq)
		return err
	}
	if resp[0] != cmd[0] {
		return fmt.Errorf("programm error, command byte differs")
	}
	if len(resp) != 3 {
		return fmt.Errorf("expecting only 3 bytes, usually OK, in case of anything else, just end this missery (it can send also ERROR or something probably)")
	}
	if resp[1] != 'O' || resp[2] != 'K' {
		return fmt.Errorf("command failed, response: 0x%02x 0x%02x", resp[1], resp[2])
	}
	return nil
}

func (m *moxaRealCom) flush() error {
	return m.handleOkCmd([]byte{ASPP_CMD_FLUSH, 0x01, 0x02}) // ASPP_CMD_FLUSH, 1, ASPP_FLUSH_ALL_BUFFER
}

func (m *moxaRealCom) Read(p []byte) (n int, err error) {
	if !m.isopen {
		return 0, base.ErrNotOpened
	}
	cerr := m.cmderr.Load()
	if cerr != nil {
		return 0, cerr.(error)
	}
	if len(p) == 0 {
		return 0, base.ErrNothingToRead
	}
	return m.transport.Read(p)
}

func (m *moxaRealCom) SetDTR(dtr bool) error {
	if !m.isopen {
		return base.ErrNotOpened
	}
	var cmd [4]byte
	// no flush here, probably...
	cmd[0] = ASPP_CMD_LINECTRL
	cmd[1] = 0x02
	if dtr {
		cmd[2] = 1
	}
	// cmd[3] is RTS
	cmd[3] = 1
	return m.handleOkCmd(cmd[:])
}

func (m *moxaRealCom) SetDeadline(t time.Time) {
	m.transport.SetDeadline(t)
}

func (m *moxaRealCom) SetFlowControl(flowControl base.SerialFlowControl) error {
	if !m.isopen {
		return base.ErrNotOpened
	}
	var cmd [6]byte
	err := m.flush()
	if err != nil {
		return err
	}
	m.settings.FlowControl = flowControl

	cmd[0] = ASPP_CMD_FLOWCTRL
	cmd[1] = 0x04
	switch m.settings.FlowControl {
	case base.SerialNoFlowControl: // keep that zero
	case base.SerialSWFlowControl:
		cmd[2] = 1 // set RTS to 1, need to check that
		cmd[4] = 1 // ixon
		cmd[5] = 1 // ixoff
	case base.SerialHWFlowControl:
		cmd[2] = 1
		cmd[3] = 1
	}
	return m.handleOkCmd(cmd[:])
}

func (m *moxaRealCom) SetLogger(logger *zap.SugaredLogger) {
	m.logger = logger
	m.transport.SetLogger(logger)
}

func (x *moxaRealCom) SetMaxReceivedBytes(m int64) {
	x.transport.SetMaxReceivedBytes(m)
}

func (m *moxaRealCom) SetSpeed(baudRate int, dataBits base.SerialDataBits, parity base.SerialParity, stopBits base.SerialStopBits) error {
	if !m.isopen {
		return base.ErrNotOpened
	}

	var cmd [4]byte
	err := m.flush()
	if err != nil {
		return err
	} // flushed hopefully, this is somewhat bad...
	m.settings.BaudRate = baudRate
	m.settings.DataBits = dataBits
	m.settings.Parity = parity
	m.settings.StopBits = stopBits

	cmd[0] = ASPP_CMD_IOCTL
	cmd[1] = 0x02
	cmd[2], err = baudstobyte(baudRate)
	if err != nil {
		return err
	}
	cmd[3] = m.modebyte()
	return m.handleOkCmd(cmd[:])
}

func (m *moxaRealCom) SetTimeout(t time.Duration) {
	m.transport.SetTimeout(t)
	m.timeout = t
}

func (m *moxaRealCom) Write(src []byte) error {
	if !m.isopen {
		return base.ErrNotOpened
	}
	cerr := m.cmderr.Load()
	if cerr != nil {
		return cerr.(error)
	}
	if len(src) == 0 {
		return nil
	}

	for ch := range slices.Chunk(src, 4096) { // a bit hardcore, it seems that max buffer according ASPP_CMD_OQUEUE can be word bytes?, lower that a bit, should be used with hdlc anyway
		err := m.transport.Write(ch)
		if err != nil {
			return err
		}
	}
	return nil
}

func New(hostname string, dataport, cmdport int, timeout time.Duration, settings *base.SerialStreamSettings) base.SerialStream {
	ret := &moxaRealCom{
		transport:   tcp.New(hostname, dataport, timeout),
		timeout:     timeout,
		isopen:      false,
		writebuffer: make([]byte, 0, 1024),
		hostname:    hostname,
		cmdport:     cmdport,
	}
	if ret.timeout == 0 {
		ret.timeout = time.Second // in case of zero, set that to 1 second
	}
	if settings != nil {
		ret.settings = *settings // at least copy
	} else { // implicit values, part of init port is setting, so at least something has to be there
		ret.settings.BaudRate = 9600
		ret.settings.DataBits = base.Serial8DataBits
		ret.settings.Parity = base.SerialNoParity
		ret.settings.StopBits = base.SerialOneStopBit
		ret.settings.FlowControl = base.SerialNoFlowControl
	}
	return ret
}
