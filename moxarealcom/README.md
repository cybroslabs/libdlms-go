# Moxa Real COM Driver

This package implements the Moxa Real COM protocol for Go, enabling communication with Moxa NPort serial device servers over TCP/IP. It provides a transparent serial communication layer that implements the `base.SerialStream` interface, similar to the RFC2217 implementation.

## Overview

Moxa Real COM is a proprietary protocol used by Moxa NPort devices to provide virtual serial ports over TCP/IP networks. This implementation is based on:

- The RFC2217 implementation pattern in this repository
- The [Moxa NPort Real TTY Linux driver](https://github.com/Moxa-Linux/moxa-nport-real-tty-utils)
- Reverse-engineered protocol specifications from the official Moxa drivers

## Protocol Details

The Moxa Real COM protocol uses the ASPP (Async Server Protocol) for serial port control:

### Command Structure

All commands follow a 4-byte header format:
```
[Command Set (1)] [Command (1)] [Length (2, Big Endian)] [Data...]
```

### Command Sets

- `NPREAL_ASPP_COMMAND_SET (1)`: ASPP protocol commands for device control
- `NPREAL_LOCAL_COMMAND_SET (2)`: Local connection state commands

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

// Create TCP transport to Moxa NPort device
// Moxa devices typically use ports 4001-4016 for Real COM mode
tcpTransport := tcp.New("192.168.1.100", 4001, 5*time.Second)

// Configure serial settings
settings := &base.SerialStreamSettings{
    BaudRate:    9600,
    DataBits:    base.Serial8DataBits,
    Parity:      base.SerialNoParity,
    StopBits:    base.SerialOneStopBit,
    FlowControl: base.SerialNoFlowControl,
}

// Create Moxa Real COM serial stream
serial := moxarealcom.New(tcpTransport, settings)

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

### Protocol Differences from RFC2217

Unlike RFC2217 which uses Telnet IAC command escaping:
- Moxa Real COM uses a simple 4-byte header structure
- No byte escaping is required for data transmission
- Control commands and data can be interleaved in the stream
- Commands are binary, not text-based

### Connection Lifecycle

1. **Open**: Sends `LOCAL_CMD_TTY_USED` to notify server
2. **Initialize**: Sends `ASPP_CMD_PORT_INIT` with serial settings
3. **Configure**: Sends flow control and line control commands
4. **Enable Notifications**: Sends `ASPP_CMD_START_NOTIFY`
5. **Operate**: Read/write data, process control commands
6. **Close**: Sends `LOCAL_CMD_TTY_UNUSED` before disconnecting

### Read Operation

The `Read()` method automatically filters out control commands from the data stream:
- Detects command headers (ASPP/LOCAL command sets)
- Processes control commands (NOTIFY, LSTATUS, POLLING)
- Returns only actual serial data to the caller

### Write Operation

Data is written directly to the transport without escaping, chunked at 2KB for optimal performance.

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

- [Moxa NPort Real TTY Utils](https://github.com/Moxa-Linux/moxa-nport-real-tty-utils)
- [Moxa Real COM Mode Documentation](https://www.moxa.com/getmedia/126eb6d8-fa0f-4fd2-bb85-4329d3c85475/moxa-real-com-mode-for-nport-tech-note-v2.0.pdf)
- RFC2217 - Telnet Com Port Control Option

## License

This implementation follows the same license as the parent project.
