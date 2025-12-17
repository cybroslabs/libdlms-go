# Moxa Real COM Driver

This package implements the Moxa Real COM protocol for Go, enabling communication with Moxa NPort serial device servers over TCP/IP. It provides a transparent serial communication layer that implements the `base.SerialStream` interface.

## Overview

Moxa Real COM is a proprietary protocol used by Moxa NPort devices to provide virtual serial ports over TCP/IP networks. This implementation is based on the official [Moxa NPort Real TTY Linux driver](https://github.com/Moxa-Linux/moxa-nport-real-tty-utils) architecture.

## Protocol Details

The Moxa Real COM protocol uses the ASPP (Async Server Protocol) for serial port control:

### Wire Protocol Format

**Commands sent TO device:**
- LOCAL commands: `[CommandSet (1)] [Command (1)]` - 2 bytes, no data
- ASPP commands: `[Command (1)] [Length (1)] [Data...]` - no CommandSet prefix

**Commands received FROM device:**
- `[Command (1)] [Data...]` - implicit length based on command type
- No command set prefix, no explicit length field
- Packet length determined by command code

### Command Sets (Internal Use)

- `NPREAL_ASPP_COMMAND_SET (1)`: ASPP protocol commands (prefix stripped on wire)
- `NPREAL_LOCAL_COMMAND_SET (2)`: Local connection state commands (sent with prefix)

### Key ASPP Commands

- **PORT_INIT (44)**: Initialize port with baud rate, data bits, parity, stop bits
- **SETBAUD (23)**: Change baud rate
- **FLOWCTRL (17)**: Set flow control (none/hardware/software)
- **LINECTRL (18)**: Control DTR/RTS modem lines
- **NOTIFY (0x26)**: Server notification of modem state changes
- **POLLING (0x27)**: Server aliveness check
- **ALIVE (0x28)**: Response to polling
- **LSTATUS (19)**: Line status notification
- **START_NOTIFY (36)**: Enable status notifications
- **STOP_NOTIFY (37)**: Disable status notifications

### Flow Control Types

- `ASPP_FLOW_NONE (0)`: No flow control
- `ASPP_FLOW_HW (1)`: Hardware flow control (RTS/CTS)
- `ASPP_FLOW_SW (2)`: Software flow control (XON/XOFF)

### Modem Control Lines

- `ASPP_MODEM_DTR (0x01)`: Data Terminal Ready
- `ASPP_MODEM_RTS (0x02)`: Request To Send

## Usage

```go
import (
    "time"
    "github.com/cybroslabs/libdlms-go/base"
    "github.com/cybroslabs/libdlms-go/moxarealcom"
    "github.com/cybroslabs/libdlms-go/tcp"
)

// Moxa Real COM protocol uses TWO separate TCP connections:
// 1. Data stream - for serial data transmission (no commands)
// 2. Command stream - for ASPP control commands only
//
// Both connections typically connect to the same port on the Moxa device
dataStream := tcp.New("192.168.1.100", 950, 5*time.Second)
commandStream := tcp.New("192.168.1.100", 966, 5*time.Second)

// Configure serial settings
settings := &base.SerialStreamSettings{
    BaudRate:    9600,
    DataBits:    base.Serial8DataBits,
    Parity:      base.SerialNoParity,
    StopBits:    base.SerialOneStopBit,
    FlowControl: base.SerialNoFlowControl,
}

// Create Moxa Real COM serial stream with dual connections
serial := moxarealcom.New(dataStream, commandStream, settings)

// Open the connection
if err := serial.Open(); err != nil {
    // handle error
}
defer serial.Disconnect()

// Use the serial interface
serial.Write([]byte("Hello, Moxa!\r\n"))
buffer := make([]byte, 256)
n, err := serial.Read(buffer)
```

## Features

- ✅ Full serial port configuration (baud rate, data bits, parity, stop bits)
- ✅ Flow control support (none, hardware, software)
- ✅ DTR/RTS control
- ✅ Line and modem state monitoring
- ✅ Connection state management
- ✅ Timeout and deadline support
- ✅ Logger integration
- ✅ Rx/Tx byte counting

## Supported Serial Settings

### Baud Rates
300, 600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600

### Data Bits
5, 6, 7, 8

### Parity
None, Odd, Even, Mark, Space

### Stop Bits
1, 1.5, 2

### Flow Control
None, Hardware (RTS/CTS), Software (XON/XOFF)

**Note**: DCD and DSR flow control are not supported by the Moxa Real COM protocol.

## Implementation Notes

### Protocol Architecture: Dual-Stream Design

The Moxa Real COM protocol uses **two separate TCP connections** (matching the official Moxa driver architecture):

1. **Data Stream**: Pure serial data transmission
   - No command processing or filtering
   - All bytes are serial data (including 0x01, 0x02)
   - No escaping required
   - Optimized for throughput

2. **Command Stream**: ASPP control commands only
   - Background goroutine processes commands
   - Handles NOTIFY, LSTATUS, POLLING, etc.
   - Isolated from data stream

This architecture **eliminates the binary data ambiguity problem** where byte sequences like `0x01 0x26 ...` in serial data could be mistaken for ASPP commands.

### Protocol Characteristics

- Dual TCP connections (separate data and command streams)
- No byte escaping required for data transmission
- Binary command protocol with 4-byte header structure
- Raw data passthrough on data stream

### Connection Lifecycle

1. **Open**: Opens both data and command streams
2. **Start Command Processor**: Background goroutine monitors command stream
3. **Initialize**: Sends `LOCAL_CMD_TTY_USED` to notify server
4. **Configure**: Sends `ASPP_CMD_PORT_INIT` with serial settings
5. **Setup Flow Control**: Sends flow control and line control commands
6. **Enable Notifications**: Sends `ASPP_CMD_START_NOTIFY`
7. **Operate**: Read/write data on data stream, commands processed in background
8. **Close**: Stops command processor, sends `LOCAL_CMD_TTY_UNUSED`, disconnects both streams

### Read Operation

The `Read()` method reads directly from the data stream with no filtering:
- Pure serial data, no command processing
- Binary-safe (any byte values including 0x01, 0x02 are valid)
- No ambiguity with command sequences

### Write Operation

Data is written directly to the data stream without escaping, chunked at 2KB for optimal performance.

## Compatibility

This implementation is designed to work with:
- Moxa NPort 5000 series
- Moxa NPort 6000 series
- Moxa NPort W2150/W2250 series
- Other Moxa devices supporting Real COM mode

## Limitations

- DCD/DSR flow control not supported (protocol limitation)
- Break signal control not yet implemented
- Queue management commands not exposed
- Secure mode (SSL/TLS) not implemented

## References

- [Moxa NPort Real TTY Linux Driver](https://github.com/Moxa-Linux/moxa-nport-real-tty-utils) - Official driver source
- [Moxa Real COM Mode Documentation](https://www.moxa.com/getmedia/126eb6d8-fa0f-4fd2-bb85-4329d3c85475/moxa-real-com-mode-for-nport-tech-note-v2.0.pdf) - Technical specification

## License

This implementation follows the same license as the parent project.
