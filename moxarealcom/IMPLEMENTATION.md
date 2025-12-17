# Moxa Real COM Implementation Notes

## Implementation Based On

This implementation is based on the official **Moxa NPort Real TTY Linux driver** architecture:
- Source: https://github.com/Moxa-Linux/moxa-nport-real-tty-utils
- Uses dual TCP connections (data + command streams)
- Matches the official driver's socket architecture

## Protocol Architecture

### Command Packet Format

**Sent TO Device:**
```
LOCAL: [CommandSet][Command]
ASPP:  [Command][Length][Data...]
```

**Received FROM Device:**
```
[Command][Data...]  (implicit length based on command type)
```

- **Command Set**: 1 byte (LOCAL=0x02) - only for LOCAL commands
- **Command**: 1 byte (command code)
- **Length**: 1 byte (data length) - only in sent ASPP commands
- **Data**: raw binary data

### Connection Handshake

1. Open both TCP connections (data and command streams)
2. Send `LOCAL_CMD_TTY_USED` notification on command stream
3. Send `ASPP_CMD_PORT_INIT` with serial configuration
4. Send `ASPP_CMD_FLOWCTRL` for flow control settings
5. Send `ASPP_CMD_LINECTRL` for DTR/RTS state
6. Send `ASPP_CMD_START_NOTIFY` to enable status updates
7. Begin data transmission

### Data Transmission

- **Data Stream**: Raw serial data without any escaping or framing
- **Command Stream**: ASPP commands processed by background goroutine
- **Binary Safe**: All byte values (0x00-0xFF) valid in data stream
- **No Multiplexing**: Commands and data never mixed

### Key ASPP Commands

| Function | Command | Code | Packet Length (RX) |
|----------|---------|------|-------------------|
| Port Initialization | ASPP_CMD_PORT_INIT | 44 | 5 bytes |
| Set Baud Rate | ASPP_CMD_SETBAUD | 23 | 3 bytes |
| Flow Control | ASPP_CMD_FLOWCTRL | 17 | 3 bytes |
| Line Control (DTR/RTS) | ASPP_CMD_LINECTRL | 18 | - |
| Flush Buffers | ASPP_CMD_FLUSH | 20 | - |
| Line Status | ASPP_CMD_LSTATUS | 19 | 5 bytes |
| Modem State | ASPP_CMD_NOTIFY | 38 (0x26) | 4 bytes |
| Keep-Alive Poll | ASPP_CMD_POLLING | 39 (0x27) | 3 bytes |
| Keep-Alive Response | ASPP_CMD_ALIVE | 40 (0x28) | 3 bytes |

## Implementation Structure

```go
type moxaRealCOMSerial struct {
    dataStream    base.Stream      // TCP data connection
    commandStream base.Stream      // TCP command connection
    isopen        bool             // Connection state
    writebuffer   []byte           // Reusable write buffer
    settings      SerialStreamSettings
    havesettings  bool
    linestate     byte             // Line status
    modemstate    byte             // Modem status
    logger        *zap.SugaredLogger

    // Command processing
    stopCmdProcessor chan struct{}
    cmdProcessorDone chan struct{}
}
```

### SerialStream Interface Implementation

The implementation provides all required `base.SerialStream` methods:

- `Open()` - Opens both streams and starts command processor
- `Close()` - Semantic close (no-op)
- `Disconnect()` - Stops command processor and closes both streams
- `Read([]byte)` - Direct passthrough from data stream
- `Write([]byte)` - Direct write to data stream
- `SetSpeed()` - Sends SETBAUD command
- `SetFlowControl()` - Sends FLOWCTRL command
- `SetDTR()` - Sends LINECTRL command
- `SetTimeout()` / `SetDeadline()` - Timeout management for data stream
- `SetLogger()` - Logging support for both streams
- `SetMaxReceivedBytes()` - Byte limiting for both streams
- `GetRxTxBytes()` - Combined statistics from both streams

### Validation Functions

Serial parameter validation:
- `sanitySpeed()` - Validates baud rate, data bits, parity, stop bits
- `sanityControl()` - Validates flow control settings
- Ensures only supported configurations are sent to device

## Connection States

1. **Closed** - Both streams disconnected
2. **Opening** - Command stream opened, initializing
3. **TTY Claimed** - `LOCAL_CMD_TTY_USED` sent
4. **Configured** - Serial parameters sent via `PORT_INIT`
5. **Notifications Enabled** - `START_NOTIFY` sent
6. **Open** - Data transfer active, command processor running
7. **Closing** - `LOCAL_CMD_TTY_UNUSED` sent, stopping processor
8. **Closed** - Both streams disconnected

## Command Processing

### Data Stream - Simple Passthrough
```go
func (m *moxaRealCOMSerial) Read(p []byte) (n int, err error) {
    // Direct passthrough - no filtering or processing
    return m.dataStream.Read(p)
}

func (m *moxaRealCOMSerial) Write(src []byte) error {
    // Direct write to data stream (chunked for large transfers)
    return m.dataStream.Write(src)
}
```

### Command Stream - Background Processor

```go
func (m *moxaRealCOMSerial) commandProcessor() {
    defer close(m.cmdProcessorDone)

    buffer := make([]byte, 1024)
    for {
        select {
        case <-m.stopCmdProcessor:
            return
        default:
        }

        // Read command from command stream
        m.commandStream.SetTimeout(100 * time.Millisecond)
        n, err := m.commandStream.Read(buffer)
        if err != nil {
            continue  // Timeout or error, keep running
        }

        // Parse 4-byte command header
        cmdSet := buffer[0]      // 0x01=ASPP, 0x02=LOCAL
        cmd := buffer[1]         // Command code
        length := binary.BigEndian.Uint16(buffer[2:4])
        cmdData := buffer[4:4+length]

        // Process based on command set
        if cmdSet == NPREAL_ASPP_COMMAND_SET {
            handleASPPCommand(cmd, cmdData)
        }
    }
}
```

### Command Handlers

```go
func (m *moxaRealCOMSerial) handleASPPCommand(cmd byte, data []byte) error {
    switch cmd {
    case ASPP_CMD_NOTIFY:
        // Modem state notification
        m.modemstate = data[0]

    case ASPP_CMD_LSTATUS:
        // Line status notification
        m.linestate = data[0]

    case ASPP_CMD_POLLING:
        // Keep-alive poll - respond with ALIVE
        response := writeCommand(ASPP_CMD_ALIVE, nil)
        return m.commandStream.Write(response)

    case ASPP_CMD_ALIVE:
        // Keep-alive response received
    }
    return nil
}
```

## Testing Recommendations

### Unit Testing
- Mock `base.Stream` for testing without actual network
- Test command packet formatting (header + data)
- Test serial parameter validation (sanitySpeed, sanityControl)
- Test state transitions (Open, Close, Disconnect)

### Integration Testing with Real Hardware
- **Binary Data Safety**: Send data containing 0x01, 0x02, and command-like sequences
- **Baud Rate Changes**: Test dynamic speed changes while connected
- **Flow Control**: Test none, hardware (RTS/CTS), and software (XON/XOFF) modes
- **DTR/RTS Control**: Verify modem line control
- **Large Transfers**: Test throughput with multi-megabyte transfers
- **Keep-Alive**: Verify POLLING/ALIVE mechanism works
- **Connection Stability**: Test reconnection after network interruption

## Performance Characteristics

### Buffer Management
- Command buffer: 1024 bytes per command (reusable)
- Write chunking: 2048 bytes per chunk (optimal for TCP)
- Data stream: Direct passthrough (no internal buffering)
- Command stream: Handled by background goroutine

### Protocol Overhead
- Command packets: 4-byte header + data
- Data stream: Zero overhead (raw passthrough)
- Efficient for binary data (no escaping needed)

## Security Considerations

### Current Implementation
- Plain TCP connections (no encryption)
- No authentication mechanism
- Suitable for trusted networks only

### Future Security Enhancements
- SSL/TLS support (Moxa NPort 6000 series supports secure mode)
- Certificate-based authentication
- Would require SSL handshake after TCP connection establishment

## Device Compatibility

### Supported Devices
- Moxa NPort 5000 series
- Moxa NPort 6000 series
- Moxa NPort W2150/W2250 series
- Other Moxa devices with Real COM mode support

### Port Configuration
- Default ports: 950/966 (device dependent)
- Both data and command streams connect to same port number
- Each stream is a separate TCP connection

### Known Limitations
1. **DCD/DSR flow control** - Not supported (protocol limitation)
2. **Break signal** - Not implemented (ASPP_CMD_START_BREAK/STOP_BREAK)
3. **Queue status** - Commands not exposed (ASPP_CMD_OQUEUE/IQUEUE)
4. **Secure mode** - SSL/TLS not implemented
5. **IPv6 DSCI** - Discovery protocol not implemented

## Implementation Roadmap

### Priority Enhancements
- [ ] Comprehensive unit tests with mock streams
- [ ] Hardware validation with actual Moxa devices
- [ ] Connection retry/reconnect logic
- [ ] Break signal control implementation

### Future Features
- [ ] SSL/TLS support for secure mode (NPort 6000 series)
- [ ] Queue management commands
- [ ] DSCI discovery protocol
- [ ] Performance optimizations
