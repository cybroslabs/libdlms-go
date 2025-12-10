# Moxa Real COM Implementation Notes

## Implementation Based On

This implementation was created by studying:

1. **RFC2217 implementation** in `rfc2217/rfc2217.go` - Used as architectural template
2. **Moxa NPort Real TTY Linux driver** - Source: https://github.com/Moxa-Linux/moxa-nport-real-tty-utils
3. **Direct Serial implementation** in `directserial/directserial.go` - Used for interface pattern

## Key Differences from RFC2217

### Protocol Format

**RFC2217 (Telnet-based):**
```
IAC SB COM_PORT_OPTION <command> <data> IAC SE
```
- Uses Telnet IAC (0xFF) byte escaping
- Commands wrapped in Telnet subnegotiation sequences
- Text-oriented protocol with option negotiation
- Command: 1 byte, Data: variable with IAC escaping

**Moxa Real COM (ASPP):**
```
[Command Set][Command][Length MSB][Length LSB][Data...]
```
- Binary protocol with fixed 4-byte header
- No byte escaping required
- Command Set: 1 byte (ASPP=1, LOCAL=2)
- Command: 1 byte
- Length: 2 bytes big-endian
- Data: raw binary, length specified in header

### Connection Handshake

**RFC2217:**
1. Negotiate Telnet BINARY mode
2. Negotiate Telnet SGA (Suppress Go Ahead)
3. Negotiate COM_PORT_OPTION (44)
4. Send signature for identification
5. Configure serial parameters via subnegotiation
6. Begin data transfer

**Moxa Real COM:**
1. Send LOCAL_CMD_TTY_USED notification
2. Send ASPP_CMD_PORT_INIT with full serial configuration
3. Send ASPP_CMD_FLOWCTRL for flow control
4. Send ASPP_CMD_LINECTRL for DTR/RTS state
5. Send ASPP_CMD_START_NOTIFY to enable status updates
6. Begin data transfer

### Data Transmission

**RFC2217:**
- All IAC bytes (0xFF) must be doubled (escaped as 0xFF 0xFF)
- Commands interspersed with data using IAC sequences
- Read operation must parse and filter Telnet commands

**Moxa Real COM:**
- Raw data transmission without escaping
- Commands have distinct header (command set 1 or 2)
- Read operation detects command headers and processes separately
- More efficient for binary data

### Command Comparison

| Function | RFC2217 Command | Moxa ASPP Command |
|----------|----------------|-------------------|
| Set Baud Rate | SB 44 1 [4 bytes] SE | ASPP_CMD_SETBAUD (23) |
| Set Data Size | SB 44 2 [1 byte] SE | ASPP_CMD_PORT_INIT (44) |
| Set Parity | SB 44 3 [1 byte] SE | ASPP_CMD_PORT_INIT (44) |
| Set Stop Size | SB 44 4 [1 byte] SE | ASPP_CMD_PORT_INIT (44) |
| Set Flow Control | SB 44 5 [1 byte] SE | ASPP_CMD_FLOWCTRL (17) |
| Set DTR | SB 44 8/9 SE | ASPP_CMD_LINECTRL (18) |
| Set RTS | SB 44 11/12 SE | ASPP_CMD_LINECTRL (18) |
| Purge Data | SB 44 12 [1 byte] SE | ASPP_CMD_FLUSH (20) |
| Line State | SB 44 106 [1 byte] SE | ASPP_CMD_LSTATUS (19) |
| Modem State | SB 44 107 [1 byte] SE | ASPP_CMD_NOTIFY (0x26) |

## Implementation Patterns Shared with RFC2217

Both implementations follow the same structural patterns:

```go
type serialStruct struct {
    transport   base.Stream      // TCP transport layer
    isopen      bool             // Connection state
    writebuffer []byte           // Reusable write buffer
    settings    SerialStreamSettings
    havesettings bool
    linestate   byte             // Line status
    modemstate  byte             // Modem status
    logger      *zap.SugaredLogger
}
```

### Common Methods

Both implement the `base.SerialStream` interface:
- `Open()` - Initialize connection and configure serial parameters
- `Close()` - Semantic close (no-op in both)
- `Disconnect()` - Actually close the connection
- `Read([]byte)` - Read data, filtering control commands
- `Write([]byte)` - Write data with protocol-specific handling
- `SetSpeed()` - Change serial parameters
- `SetFlowControl()` - Change flow control
- `SetDTR()` - Control DTR line
- `SetTimeout()` / `SetDeadline()` - Timeout management
- `SetLogger()` - Logging support
- `SetMaxReceivedBytes()` - Byte limiting
- `GetRxTxBytes()` - Statistics

### Validation Functions

Both include sanity checking:
- `sanitySpeed()` - Validates baud rate, data bits, parity, stop bits
- `sanityControl()` - Validates flow control settings

## Protocol State Machine

### RFC2217 States
1. Closed
2. Telnet negotiation
3. COM port negotiation
4. Configured
5. Open (data transfer)
6. Closing

### Moxa Real COM States
1. Closed
2. TTY claimed (LOCAL_CMD_TTY_USED sent)
3. Port initialized
4. Notifications enabled
5. Open (data transfer)
6. Closing (LOCAL_CMD_TTY_UNUSED sent)

## Command Processing

### RFC2217
```go
func (r *rfc2217Serial) Read(p []byte) (n int, err error) {
    for len(p) > 0 {
        read byte
        if byte == IAC {
            read next byte
            if next != IAC {
                processCommand(next)  // Telnet command
            } else {
                p[n] = IAC  // Escaped IAC byte
                n++
            }
        } else {
            p[n] = byte  // Data byte
            n++
        }
    }
}
```

### Moxa Real COM
```go
func (m *moxaRealCOMSerial) Read(p []byte) (n int, err error) {
    for n < len(p) {
        peek first byte
        if byte == NPREAL_ASPP_COMMAND_SET || byte == NPREAL_LOCAL_COMMAND_SET {
            read full command header (4 bytes)
            read command data (length from header)
            processCommand(cmdSet, cmd, data)
        } else {
            p[n] = byte  // Data byte
            n++
        }
    }
}
```

## Testing Considerations

### Unit Testing
- Mock `base.Stream` for testing without actual network
- Test command formatting with known good packets
- Test serial parameter validation
- Test state transitions

### Integration Testing
- Requires actual Moxa NPort device or simulator
- Test with various baud rates and configurations
- Test DTR/RTS control
- Test flow control modes
- Test large data transfers
- Test command/data interleaving

## Performance Characteristics

### Buffer Management
- Write buffer: 1024 bytes initial capacity
- Write chunking: 2048 bytes per chunk
- No read buffering (relies on TCP transport buffering)

### Overhead Comparison
- **RFC2217**: 5 bytes per command + IAC escaping in data
- **Moxa Real COM**: 4 bytes per command, no data escaping
- Moxa Real COM is more efficient for binary data transfers

## Security Considerations

### Current Implementation
- No encryption support
- Plain TCP connection
- No authentication

### Future Enhancements
- SSL/TLS support (Moxa NPort 6000 series supports secure mode)
- Would require SSL handshake after TCP connection
- OpenSSL integration (as used in official driver)

## Compatibility Notes

### Tested Devices
- Implementation based on protocol reverse engineering
- Should work with Moxa NPort 5000/6000 series
- May require testing with actual hardware

### Known Limitations
1. DCD/DSR flow control not supported (protocol limitation)
2. Break signal control not implemented
3. Queue status commands not exposed
4. Secure mode not implemented
5. IPv6 DSCI commands not implemented
6. Redundancy features not implemented

## Future Work

- [ ] Implement break signal control (ASPP_CMD_START_BREAK/STOP_BREAK)
- [ ] Add queue management (ASPP_CMD_OQUEUE/IQUEUE)
- [ ] Add SSL/TLS support for secure mode
- [ ] Improve read buffering for better performance
- [ ] Add comprehensive unit tests
- [ ] Test with actual Moxa hardware
- [ ] Add connection retry logic
- [ ] Implement DSCI discovery protocol (optional)
