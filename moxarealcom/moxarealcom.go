package moxarealcom

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"go.uber.org/zap"
)

// ASPP (Async Server Protocol) Command Codes
const (
	ASPP_CMD_IOCTL        = 16
	ASPP_CMD_FLOWCTRL     = 17
	ASPP_CMD_LINECTRL     = 18
	ASPP_CMD_LSTATUS      = 19
	ASPP_CMD_FLUSH        = 20
	ASPP_CMD_IQUEUE       = 21
	ASPP_CMD_OQUEUE       = 22
	ASPP_CMD_SETBAUD      = 23
	ASPP_CMD_XONXOFF      = 24
	ASPP_CMD_SETXON       = 25
	ASPP_CMD_NOTIFY       = 38
	ASPP_CMD_POLLING      = 39
	ASPP_CMD_ALIVE        = 40
	ASPP_CMD_START_BREAK  = 33
	ASPP_CMD_STOP_BREAK   = 34
	ASPP_CMD_START_NOTIFY = 36
	ASPP_CMD_STOP_NOTIFY  = 37
	ASPP_CMD_HOST         = 43
	ASPP_CMD_PORT_INIT    = 44
	ASPP_CMD_WAIT_OQUEUE  = 47
	ASPP_CMD_TX_FIFO      = 48

	// Command Set Types
	NPREAL_ASPP_COMMAND_SET  = 1
	NPREAL_LOCAL_COMMAND_SET = 2

	// Local Commands
	LOCAL_CMD_TTY_USED   = 1
	LOCAL_CMD_TTY_UNUSED = 2

	// Modem Control Lines (for LINECTRL)
	ASPP_MODEM_DTR = 1
	ASPP_MODEM_RTS = 2

	// Flow Control Types
	ASPP_FLOW_NONE = 0
	ASPP_FLOW_HW   = 1
	ASPP_FLOW_SW   = 2

	// Buffer sizes
	writeChunk = 2048
)

type moxaRealCOMSerial struct {
	transport   base.Stream // usually tcp
	isopen      bool
	writebuffer []byte
	readbuffer  []byte

	settings     base.SerialStreamSettings
	havesettings bool

	// status variables
	linestate  byte
	modemstate byte

	logger *zap.SugaredLogger
}

func (m *moxaRealCOMSerial) logf(format string, v ...any) {
	if m.logger != nil {
		m.logger.Infof(format, v...)
	}
}

// Close implements SerialStream.
func (m *moxaRealCOMSerial) Close() error {
	return nil // just do nothing, yes, bad semantic, should be renamed
}

// Disconnect implements SerialStream.
func (m *moxaRealCOMSerial) Disconnect() error {
	if m.isopen {
		// Send TTY_UNUSED notification
		m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_LOCAL_COMMAND_SET, LOCAL_CMD_TTY_UNUSED, nil)
		_ = m.transport.Write(m.writebuffer) // ignore error on disconnect
		m.isopen = false
	}
	return m.transport.Disconnect()
}

// GetRxTxBytes implements SerialStream.
func (m *moxaRealCOMSerial) GetRxTxBytes() (int64, int64) {
	return m.transport.GetRxTxBytes()
}

// Open implements SerialStream.
func (m *moxaRealCOMSerial) Open() error {
	if m.isopen {
		return nil
	}

	if m.havesettings {
		if err := sanityControl(m.settings.FlowControl); err != nil {
			return err
		}
		if err := sanitySpeed(m.settings.BaudRate, m.settings.DataBits, m.settings.Parity, m.settings.StopBits); err != nil {
			return err
		}
	}

	if err := m.transport.Open(); err != nil {
		return err
	}

	m.logf("initializing moxa real com connection")

	// Send TTY_USED notification
	m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_LOCAL_COMMAND_SET, LOCAL_CMD_TTY_USED, nil)

	// Send PORT_INIT if we have settings
	if m.havesettings {
		// PORT_INIT command payload: baud(4) + databits(1) + stopbits(1) + parity(1)
		initData := make([]byte, 7)
		binary.BigEndian.PutUint32(initData[0:4], uint32(m.settings.BaudRate))
		initData[4] = byte(m.settings.DataBits)
		initData[5] = byte(m.settings.StopBits)
		initData[6] = byte(m.settings.Parity)
		m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_PORT_INIT, initData)

		// Set flow control
		flowData := []byte{byte(moxaFlowControl(m.settings.FlowControl))}
		m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_FLOWCTRL, flowData)

		// Set DTR and RTS high for no flow control
		if m.settings.FlowControl == base.SerialNoFlowControl {
			lineData := []byte{ASPP_MODEM_DTR | ASPP_MODEM_RTS}
			m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_LINECTRL, lineData)
		}
	}

	// Send START_NOTIFY to receive status updates
	m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_START_NOTIFY, nil)

	if err := m.transport.Write(m.writebuffer); err != nil {
		_ = m.transport.Disconnect()
		return err
	}

	m.isopen = true
	return nil
}

// writeCommand creates a Moxa Real COM command packet
// Format: [command_set(1)][command(1)][length(2,BE)][data...]
func (m *moxaRealCOMSerial) writeCommand(dst []byte, cmdSet byte, cmd byte, data []byte) []byte {
	dst = append(dst, cmdSet, cmd)
	dataLen := len(data)
	dst = append(dst, byte(dataLen>>8), byte(dataLen))
	if dataLen > 0 {
		dst = append(dst, data...)
	}
	return dst
}

// isValidASPPCommand checks if a byte is a valid ASPP command code
func isValidASPPCommand(cmd byte) bool {
	switch cmd {
	case ASPP_CMD_IOCTL, ASPP_CMD_FLOWCTRL, ASPP_CMD_LINECTRL,
		ASPP_CMD_LSTATUS, ASPP_CMD_FLUSH, ASPP_CMD_IQUEUE,
		ASPP_CMD_OQUEUE, ASPP_CMD_SETBAUD, ASPP_CMD_XONXOFF,
		ASPP_CMD_SETXON, ASPP_CMD_NOTIFY, ASPP_CMD_POLLING,
		ASPP_CMD_ALIVE, ASPP_CMD_START_BREAK, ASPP_CMD_STOP_BREAK,
		ASPP_CMD_START_NOTIFY, ASPP_CMD_STOP_NOTIFY, ASPP_CMD_HOST,
		ASPP_CMD_PORT_INIT, ASPP_CMD_WAIT_OQUEUE, ASPP_CMD_TX_FIFO:
		return true
	default:
		return false
	}
}

// handleASPPCommand processes ASPP protocol commands
func (m *moxaRealCOMSerial) handleASPPCommand(cmd byte, data []byte) error {
	switch cmd {
	case ASPP_CMD_NOTIFY:
		if len(data) >= 1 {
			m.modemstate = data[0]
			m.logf("modem state notify: %02x", m.modemstate)
		}
	case ASPP_CMD_LSTATUS:
		if len(data) >= 1 {
			m.linestate = data[0]
			m.logf("line state: %02x", m.linestate)
		}
	case ASPP_CMD_POLLING:
		// Respond with ALIVE
		m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_ASPP_COMMAND_SET, ASPP_CMD_ALIVE, nil)
		return m.transport.Write(m.writebuffer)
	case ASPP_CMD_ALIVE:
		m.logf("received alive response")
	default:
		m.logf("unhandled ASPP command: %d (length: %d)", cmd, len(data))
	}
	return nil
}

// Read implements SerialStream.
// In Moxa Real COM mode, ASPP control commands and serial data are multiplexed on the same
// TCP connection. This function filters out ASPP commands and returns only serial data.
func (m *moxaRealCOMSerial) Read(p []byte) (n int, err error) {
	if !m.isopen {
		return 0, base.ErrNotOpened
	}
	if len(p) == 0 {
		return 0, base.ErrNothingToRead
	}

	// Return buffered data from previous reads if available
	if len(m.readbuffer) > 0 {
		n = copy(p, m.readbuffer)
		m.readbuffer = m.readbuffer[n:]
		return n, nil
	}

	// Read and process data from transport until we have serial data to return
	for {
		// Read a chunk from transport
		tmpBuf := make([]byte, len(p))
		nn, err := m.transport.Read(tmpBuf)
		if err != nil {
			return 0, err
		}
		if nn == 0 {
			return 0, io.EOF
		}
		tmpBuf = tmpBuf[:nn]

		// Scan through buffer, separating ASPP commands from serial data
		i := 0
		for i < len(tmpBuf) {
			// Check if this looks like a command header (starts with 0x01 or 0x02)
			if i+3 < len(tmpBuf) && m.isCommandHeader(tmpBuf[i:]) {
				cmdSet := tmpBuf[i]
				cmd := tmpBuf[i+1]
				length := int(binary.BigEndian.Uint16(tmpBuf[i+2 : i+4]))
				totalCmdLen := 4 + length

				// Validate: is this a real command or just data that looks like one?
				if m.validateCommand(cmdSet, cmd, length) && i+totalCmdLen <= len(tmpBuf) {
					// Valid command with complete data - process it
					var cmdData []byte
					if length > 0 {
						cmdData = tmpBuf[i+4 : i+totalCmdLen]
					}
					m.processCommand(cmdSet, cmd, cmdData)
					i += totalCmdLen
					continue
				}
			}

			// Not a command (or incomplete command) - treat as serial data
			m.readbuffer = append(m.readbuffer, tmpBuf[i])
			i++
		}

		// Return any collected serial data
		if len(m.readbuffer) > 0 {
			n = copy(p, m.readbuffer)
			m.readbuffer = m.readbuffer[n:]
			return n, nil
		}

		// No serial data collected yet, continue reading
	}
}

// isCommandHeader checks if the buffer starts with an ASPP or LOCAL command set byte
func (m *moxaRealCOMSerial) isCommandHeader(buf []byte) bool {
	return len(buf) >= 4 && (buf[0] == NPREAL_ASPP_COMMAND_SET || buf[0] == NPREAL_LOCAL_COMMAND_SET)
}

// validateCommand validates that a potential command header is a real ASPP/LOCAL command
// by checking the command code and length are reasonable.
func (m *moxaRealCOMSerial) validateCommand(cmdSet, cmd byte, length int) bool {
	// Length must be reasonable (commands typically have small payloads)
	if length < 0 || length > 256 {
		return false
	}

	switch cmdSet {
	case NPREAL_ASPP_COMMAND_SET:
		return isValidASPPCommand(cmd)
	case NPREAL_LOCAL_COMMAND_SET:
		return cmd == LOCAL_CMD_TTY_USED || cmd == LOCAL_CMD_TTY_UNUSED
	default:
		return false
	}
}

// processCommand processes a validated ASPP or LOCAL command
func (m *moxaRealCOMSerial) processCommand(cmdSet, cmd byte, data []byte) {
	if cmdSet == NPREAL_ASPP_COMMAND_SET {
		if err := m.handleASPPCommand(cmd, data); err != nil {
			m.logf("error processing ASPP command %d: %v", cmd, err)
		}
	} else {
		m.logf("received local command: %d", cmd)
	}
}

func (m *moxaRealCOMSerial) SetTimeout(t time.Duration) {
	m.transport.SetTimeout(t)
}

// SetDeadline implements SerialStream.
func (m *moxaRealCOMSerial) SetDeadline(t time.Time) {
	m.transport.SetDeadline(t)
}

// SetLogger implements SerialStream.
func (m *moxaRealCOMSerial) SetLogger(logger *zap.SugaredLogger) {
	m.logger = logger
	m.transport.SetLogger(logger)
}

// SetMaxReceivedBytes implements SerialStream.
func (m *moxaRealCOMSerial) SetMaxReceivedBytes(max int64) {
	m.transport.SetMaxReceivedBytes(max)
}

func (m *moxaRealCOMSerial) SetDTR(dtr bool) error {
	if !m.isopen {
		return base.ErrNotOpened
	}

	lineCtrl := byte(0)
	if dtr {
		lineCtrl |= ASPP_MODEM_DTR
	}
	// Keep RTS state (read current state or default to on)
	lineCtrl |= ASPP_MODEM_RTS

	m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_ASPP_COMMAND_SET, ASPP_CMD_LINECTRL, []byte{lineCtrl})
	return m.transport.Write(m.writebuffer)
}

// SetFlowControl implements SerialStream.
func (m *moxaRealCOMSerial) SetFlowControl(flowControl base.SerialFlowControl) error {
	if !m.isopen {
		return base.ErrNotOpened
	}

	if err := sanityControl(flowControl); err != nil {
		return err
	}

	m.settings.FlowControl = flowControl

	flowData := []byte{byte(moxaFlowControl(flowControl))}
	m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_ASPP_COMMAND_SET, ASPP_CMD_FLOWCTRL, flowData)

	// Set RTS/DTR for no flow control
	if flowControl == base.SerialNoFlowControl {
		lineData := []byte{ASPP_MODEM_DTR | ASPP_MODEM_RTS}
		m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_LINECTRL, lineData)
	}

	return m.transport.Write(m.writebuffer)
}

// moxaFlowControl converts base flow control to Moxa ASPP flow control
func moxaFlowControl(fc base.SerialFlowControl) byte {
	switch fc {
	case base.SerialNoFlowControl:
		return ASPP_FLOW_NONE
	case base.SerialSWFlowControl:
		return ASPP_FLOW_SW
	case base.SerialHWFlowControl:
		return ASPP_FLOW_HW
	default:
		return ASPP_FLOW_NONE
	}
}

func sanityControl(flowControl base.SerialFlowControl) error {
	switch flowControl {
	case base.SerialNoFlowControl, base.SerialSWFlowControl, base.SerialHWFlowControl:
		return nil
	case base.SerialDCDFlowControl, base.SerialDSRFlowControl:
		return fmt.Errorf("unsupported flow control %d (DCD/DSR not supported by Moxa Real COM)", flowControl)
	default:
		return fmt.Errorf("unsupported flow control %d", flowControl)
	}
}

func sanitySpeed(baudRate int, dataBits base.SerialDataBits, parity base.SerialParity, stopBits base.SerialStopBits) error {
	switch baudRate {
	case 300, 600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600:
	default:
		return fmt.Errorf("unsupported baud rate %d", baudRate)
	}
	switch dataBits {
	case base.Serial5DataBits, base.Serial6DataBits, base.Serial7DataBits, base.Serial8DataBits:
	default:
		return fmt.Errorf("unsupported data bits %d", dataBits)
	}
	switch parity {
	case base.SerialNoParity, base.SerialOddParity, base.SerialEvenParity, base.SerialMarkParity, base.SerialSpaceParity:
	default:
		return fmt.Errorf("unsupported parity %d", parity)
	}
	switch stopBits {
	case base.SerialOneStopBit, base.SerialTwoStopBits, base.SerialOneAndHalfStopBits:
	default:
		return fmt.Errorf("unsupported stop bits %d", stopBits)
	}

	return nil
}

// SetSpeed implements SerialStream.
func (m *moxaRealCOMSerial) SetSpeed(baudRate int, dataBits base.SerialDataBits, parity base.SerialParity, stopBits base.SerialStopBits) error {
	if !m.isopen {
		return base.ErrNotOpened
	}

	if err := sanitySpeed(baudRate, dataBits, parity, stopBits); err != nil {
		return err
	}

	m.settings.BaudRate = baudRate
	m.settings.DataBits = dataBits
	m.settings.Parity = parity
	m.settings.StopBits = stopBits

	// Send SETBAUD command
	baudData := make([]byte, 4)
	binary.BigEndian.PutUint32(baudData, uint32(baudRate))
	m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_ASPP_COMMAND_SET, ASPP_CMD_SETBAUD, baudData)

	// Send LINECTRL for data bits, parity, stop bits
	// Note: The actual encoding may vary by device - this is a simplified version
	// In practice, these might be combined into PORT_INIT or separate commands
	lineCtrlData := []byte{byte(dataBits), byte(parity), byte(stopBits)}
	m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_LINECTRL, lineCtrlData)

	return m.transport.Write(m.writebuffer)
}

// Write implements SerialStream.
func (m *moxaRealCOMSerial) Write(src []byte) error {
	if !m.isopen {
		return base.ErrNotOpened
	}
	if len(src) == 0 {
		return nil
	}

	// Moxa Real COM sends raw data without escaping
	// However, we should chunk large writes to avoid buffer issues
	for len(src) > 0 {
		chunk := src
		if len(chunk) > writeChunk {
			chunk = src[:writeChunk]
		}

		if err := m.transport.Write(chunk); err != nil {
			return err
		}

		src = src[len(chunk):]
	}

	return nil
}

// New creates a new Moxa Real COM serial stream
func New(t base.Stream, settings *base.SerialStreamSettings) base.SerialStream {
	ret := &moxaRealCOMSerial{
		transport:   t,
		isopen:      false,
		writebuffer: make([]byte, 0, 1024),
		readbuffer:  make([]byte, 0, 1024),
	}
	if settings != nil {
		ret.havesettings = true
		ret.settings = *settings // copy settings
	}
	return ret
}
