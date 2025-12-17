package moxarealcom

import (
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
	ASPP_CMD_PORT_RESET   = 32
	ASPP_CMD_START_BREAK  = 33
	ASPP_CMD_STOP_BREAK   = 34
	ASPP_CMD_START_NOTIFY = 36
	ASPP_CMD_STOP_NOTIFY  = 37
	ASPP_CMD_NOTIFY       = 0x26 // 38 decimal
	ASPP_CMD_POLLING      = 0x27 // 39 decimal
	ASPP_CMD_ALIVE        = 0x28 // 40 decimal
	ASPP_CMD_HOST         = 43
	ASPP_CMD_PORT_INIT    = 44
	ASPP_CMD_RESENT_TIME  = 46
	ASPP_CMD_WAIT_OQUEUE  = 47
	ASPP_CMD_TX_FIFO      = 48
	ASPP_CMD_SETXON       = 51
	ASPP_CMD_SETXOFF      = 52

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

	// Notification Flags (for ASPP_CMD_NOTIFY)
	ASPP_NOTIFY_PARITY      = 0x01
	ASPP_NOTIFY_FRAMING     = 0x02
	ASPP_NOTIFY_HW_OVERRUN  = 0x04
	ASPP_NOTIFY_SW_OVERRUN  = 0x08
	ASPP_NOTIFY_BREAK       = 0x10
	ASPP_NOTIFY_MSR_CHG     = 0x20

	// Flush Buffer Types (for ASPP_CMD_FLUSH)
	ASPP_FLUSH_RX  = 0
	ASPP_FLUSH_TX  = 1
	ASPP_FLUSH_ALL = 2

	// Buffer sizes
	writeChunk = 2048
)

type moxaRealCOMSerial struct {
	dataStream    base.Stream // TCP connection for serial data
	commandStream base.Stream // TCP connection for ASPP commands
	isopen        bool
	writebuffer   []byte

	settings     base.SerialStreamSettings
	havesettings bool

	// status variables
	linestate  byte
	modemstate byte

	logger *zap.SugaredLogger

	// command processing
	stopCmdProcessor chan struct{}
	cmdProcessorDone chan struct{}
}

func (m *moxaRealCOMSerial) logf(format string, v ...any) {
	if m.logger != nil {
		m.logger.Infof(format, v...)
	}
}

// baudRateToIndex converts a baud rate value to its ASPP protocol index
func baudRateToIndex(baud int) (byte, error) {
	baudMap := map[int]byte{
		300:    0,
		600:    1,
		1200:   2,
		2400:   3,
		4800:   4,
		9600:   5,
		19200:  6,
		38400:  7,
		57600:  8,
		115200: 10,
		230400: 11,
		460800: 12,
		921600: 13,
		150:    14,
		134:    15,
		110:    16,
		75:     17,
		50:     18,
	}
	if idx, ok := baudMap[baud]; ok {
		return idx, nil
	}
	return 0xff, fmt.Errorf("unsupported baud rate: %d", baud)
}

// packModeByte packs data bits, stop bits, and parity into a single mode byte
// Bits 0-1: Data bits (0=5, 1=6, 2=7, 3=8)
// Bit 2:    Stop bits (0=1 bit, 1=2 bits)
// Bits 3-5: Parity (0=None, 1=Even, 2=Odd, 3=Mark, 4=Space)
func packModeByte(dataBits base.SerialDataBits, stopBits base.SerialStopBits, parity base.SerialParity) byte {
	mode := byte(0)
	// Data bits: 5→0, 6→1, 7→2, 8→3
	mode |= byte(dataBits - 5)
	// Stop bits: 1→0, 2→4
	if stopBits == base.SerialTwoStopBits {
		mode |= 0x04
	}
	// Parity: None→0, Even→8, Odd→16, Mark→24, Space→32
	switch parity {
	case base.SerialEvenParity:
		mode |= 0x08
	case base.SerialOddParity:
		mode |= 0x10
	case base.SerialMarkParity:
		mode |= 0x18
	case base.SerialSpaceParity:
		mode |= 0x20
	}
	return mode
}

// Close implements SerialStream.
func (m *moxaRealCOMSerial) Close() error {
	return nil // just do nothing, yes, bad semantic, should be renamed
}

// Disconnect implements SerialStream.
func (m *moxaRealCOMSerial) Disconnect() error {
	if m.isopen {
		// Stop command processor
		close(m.stopCmdProcessor)
		<-m.cmdProcessorDone

		// Send TTY_UNUSED notification
		m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_LOCAL_COMMAND_SET, LOCAL_CMD_TTY_UNUSED, nil)
		_ = m.commandStream.Write(m.writebuffer) // ignore error on disconnect
		m.isopen = false
	}
	// Disconnect both streams
	errCmd := m.commandStream.Disconnect()
	errData := m.dataStream.Disconnect()
	if errCmd != nil {
		return errCmd
	}
	return errData
}

// GetRxTxBytes implements SerialStream.
func (m *moxaRealCOMSerial) GetRxTxBytes() (int64, int64) {
	// Sum bytes from both streams
	rxData, txData := m.dataStream.GetRxTxBytes()
	rxCmd, txCmd := m.commandStream.GetRxTxBytes()
	return rxData + rxCmd, txData + txCmd
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

	// Open both streams
	if err := m.commandStream.Open(); err != nil {
		return err
	}
	if err := m.dataStream.Open(); err != nil {
		_ = m.commandStream.Disconnect()
		return err
	}

	m.logf("initializing moxa real com connection")

	// Initialize command processor channels
	m.stopCmdProcessor = make(chan struct{})
	m.cmdProcessorDone = make(chan struct{})

	// Start command processor goroutine
	go m.commandProcessor()

	// Send TTY_USED notification
	m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_LOCAL_COMMAND_SET, LOCAL_CMD_TTY_USED, nil)

	// Send PORT_INIT if we have settings
	if m.havesettings {
		// PORT_INIT: [cmd][0x08][baud_idx][mode][dtr][rts][rts_flow][cts_flow][xon][xoff]
		baudIdx, err := baudRateToIndex(m.settings.BaudRate)
		if err != nil {
			close(m.stopCmdProcessor)
			<-m.cmdProcessorDone
			_ = m.commandStream.Disconnect()
			_ = m.dataStream.Disconnect()
			return err
		}
		mode := packModeByte(m.settings.DataBits, m.settings.StopBits, m.settings.Parity)

		// Flow control settings
		var rtsFlow, ctsFlow, xon, xoff byte
		switch m.settings.FlowControl {
		case base.SerialHWFlowControl:
			rtsFlow, ctsFlow = 1, 1
		case base.SerialSWFlowControl:
			xon, xoff = 1, 1
		}

		// DTR and RTS default to high (1)
		initData := []byte{baudIdx, mode, 1, 1, rtsFlow, ctsFlow, xon, xoff}
		m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_PORT_INIT, initData)
	}

	// Send START_NOTIFY to receive status updates
	m.writebuffer = m.writeCommand(m.writebuffer, NPREAL_ASPP_COMMAND_SET, ASPP_CMD_START_NOTIFY, nil)

	if err := m.commandStream.Write(m.writebuffer); err != nil {
		close(m.stopCmdProcessor)
		<-m.cmdProcessorDone
		_ = m.commandStream.Disconnect()
		_ = m.dataStream.Disconnect()
		return err
	}

	m.isopen = true
	return nil
}

// writeCommand creates a Moxa Real COM command packet
// Format sent to device wire protocol:
//   - LOCAL commands: [command_set(1)][command(1)] (2 bytes, no length/data)
//   - ASPP commands:  [command(1)][length(1)][data...] (no command_set prefix)
func (m *moxaRealCOMSerial) writeCommand(dst []byte, cmdSet byte, cmd byte, data []byte) []byte {
	dataLen := len(data)
	if dataLen > 255 {
		panic(fmt.Sprintf("command data too large: %d bytes (max 255)", dataLen))
	}

	if cmdSet == NPREAL_LOCAL_COMMAND_SET {
		// LOCAL commands: just [cmdSet][cmd], no length or data
		dst = append(dst, cmdSet, cmd)
	} else {
		// ASPP commands: [cmd][length][data] - NO cmdSet prefix on wire
		dst = append(dst, cmd, byte(dataLen))
		if dataLen > 0 {
			dst = append(dst, data...)
		}
	}
	return dst
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
		// Respond with ALIVE, echoing the sequence ID from the POLLING command
		// POLLING format: [cmd][length][sequence_id]
		// ALIVE format: [cmd][0x01][sequence_id]
		if len(data) >= 2 {
			sequenceID := data[1]
			m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_ASPP_COMMAND_SET, ASPP_CMD_ALIVE, []byte{sequenceID})
			return m.commandStream.Write(m.writebuffer)
		}
	case ASPP_CMD_ALIVE:
		m.logf("received alive response")
	default:
		m.logf("unhandled ASPP command: %d (length: %d)", cmd, len(data))
	}
	return nil
}

// getCommandLength returns the expected packet length for a given command
// Based on modbus-gate aspp.c and npreal2d.c implementations
func getCommandLength(cmd byte) int {
	switch cmd {
	// 3-byte commands: [cmd][0x01][data]
	case ASPP_CMD_FLOWCTRL, ASPP_CMD_IOCTL, ASPP_CMD_SETBAUD, ASPP_CMD_LINECTRL,
		ASPP_CMD_START_BREAK, ASPP_CMD_STOP_BREAK, ASPP_CMD_START_NOTIFY, ASPP_CMD_STOP_NOTIFY,
		ASPP_CMD_FLUSH, ASPP_CMD_HOST, ASPP_CMD_TX_FIFO, ASPP_CMD_XONXOFF,
		ASPP_CMD_SETXON, ASPP_CMD_SETXOFF, ASPP_CMD_POLLING, ASPP_CMD_ALIVE:
		return 3
	// 4-byte commands: [cmd][0x02][data1][data2]
	case ASPP_CMD_NOTIFY, ASPP_CMD_WAIT_OQUEUE, ASPP_CMD_OQUEUE, ASPP_CMD_IQUEUE:
		return 4
	// 5-byte commands: [cmd][0x03][data1][data2][data3]
	case ASPP_CMD_LSTATUS:
		return 5
	// 10-byte command: [cmd][0x08][8 data bytes]
	case ASPP_CMD_PORT_INIT:
		return 10
	default:
		// Unknown command, consume 1 byte and skip
		return 1
	}
}

// commandProcessor runs in a background goroutine to process commands from the command stream
// Device sends: [Cmd][Data...] with implicit length based on command type
func (m *moxaRealCOMSerial) commandProcessor() {
	defer close(m.cmdProcessorDone)

	buffer := make([]byte, 1024)
	bufferLen := 0

	for {
		select {
		case <-m.stopCmdProcessor:
			return
		default:
		}

		// Set short timeout for responsive shutdown
		m.commandStream.SetTimeout(100 * time.Millisecond)

		n, err := m.commandStream.Read(buffer[bufferLen:])
		if err != nil {
			if err == io.EOF {
				return
			}
			// Timeout or temporary error, continue
			continue
		}

		bufferLen += n

		// Process all complete commands in buffer
		offset := 0
		for offset < bufferLen {
			if bufferLen-offset < 1 {
				break
			}

			cmd := buffer[offset]
			packetLen := getCommandLength(cmd)

			if bufferLen-offset < packetLen {
				// Incomplete packet, wait for more data
				break
			}

			// Extract command data (everything except the command byte)
			var cmdData []byte
			if packetLen > 1 {
				cmdData = buffer[offset+1 : offset+packetLen]
			}

			// Process the command
			if err := m.handleASPPCommand(cmd, cmdData); err != nil {
				m.logf("error processing ASPP command %d: %v", cmd, err)
			}

			offset += packetLen
		}

		// Shift remaining data to beginning of buffer
		if offset > 0 {
			copy(buffer, buffer[offset:bufferLen])
			bufferLen -= offset
		}
	}
}

// Read implements SerialStream.
// With dual-stream architecture, this reads pure serial data from the data stream.
// Commands are handled separately by the command processor goroutine.
func (m *moxaRealCOMSerial) Read(p []byte) (n int, err error) {
	if !m.isopen {
		return 0, base.ErrNotOpened
	}
	if len(p) == 0 {
		return 0, base.ErrNothingToRead
	}

	// Read directly from data stream - no command filtering needed
	return m.dataStream.Read(p)
}

func (m *moxaRealCOMSerial) SetTimeout(t time.Duration) {
	m.dataStream.SetTimeout(t)
	// Don't set timeout on command stream as it has its own internal timeout
}

// SetDeadline implements SerialStream.
func (m *moxaRealCOMSerial) SetDeadline(t time.Time) {
	m.dataStream.SetDeadline(t)
	// Don't set deadline on command stream
}

// SetLogger implements SerialStream.
func (m *moxaRealCOMSerial) SetLogger(logger *zap.SugaredLogger) {
	m.logger = logger
	m.dataStream.SetLogger(logger)
	m.commandStream.SetLogger(logger)
}

// SetMaxReceivedBytes implements SerialStream.
func (m *moxaRealCOMSerial) SetMaxReceivedBytes(max int64) {
	m.dataStream.SetMaxReceivedBytes(max)
	m.commandStream.SetMaxReceivedBytes(max)
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
	return m.commandStream.Write(m.writebuffer)
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

	return m.commandStream.Write(m.writebuffer)
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
// Note: Dynamically changing serial parameters after PORT_INIT requires sending
// a new PORT_INIT command with all parameters, not just SETBAUD.
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

	// Send complete PORT_INIT with new parameters
	baudIdx, err := baudRateToIndex(baudRate)
	if err != nil {
		return err
	}
	mode := packModeByte(dataBits, stopBits, parity)

	// Preserve current flow control settings
	var rtsFlow, ctsFlow, xon, xoff byte
	switch m.settings.FlowControl {
	case base.SerialHWFlowControl:
		rtsFlow, ctsFlow = 1, 1
	case base.SerialSWFlowControl:
		xon, xoff = 1, 1
	}

	initData := []byte{baudIdx, mode, 1, 1, rtsFlow, ctsFlow, xon, xoff}
	m.writebuffer = m.writeCommand(m.writebuffer[:0], NPREAL_ASPP_COMMAND_SET, ASPP_CMD_PORT_INIT, initData)

	return m.commandStream.Write(m.writebuffer)
}

// Write implements SerialStream.
func (m *moxaRealCOMSerial) Write(src []byte) error {
	if !m.isopen {
		return base.ErrNotOpened
	}
	if len(src) == 0 {
		return nil
	}

	// Moxa Real COM sends raw data without escaping on the data stream
	// However, we should chunk large writes to avoid buffer issues
	for len(src) > 0 {
		chunk := src
		if len(chunk) > writeChunk {
			chunk = src[:writeChunk]
		}

		if err := m.dataStream.Write(chunk); err != nil {
			return err
		}

		src = src[len(chunk):]
	}

	return nil
}

// New creates a new Moxa Real COM serial stream with dual TCP connections.
// The Moxa Real COM protocol uses two separate TCP connections:
//   - dataStream: Pure serial data transmission (no commands)
//   - commandStream: ASPP control commands only
//
// Typically, Moxa NPort devices use sequential ports:
//   - Port N (e.g., 950): Data connection
//   - Port N (e.g., 966): Command connection (same port, separate connection)
//
// Some devices may use different port numbers - consult your device documentation.
func New(dataStream base.Stream, commandStream base.Stream, settings *base.SerialStreamSettings) base.SerialStream {
	ret := &moxaRealCOMSerial{
		dataStream:    dataStream,
		commandStream: commandStream,
		isopen:        false,
		writebuffer:   make([]byte, 0, 1024),
	}
	if settings != nil {
		ret.havesettings = true
		ret.settings = *settings // copy settings
	}
	return ret
}
