# libdlms-go

A comprehensive Go implementation of the DLMS/COSEM (Device Language Message Specification / Companion Specification for Energy Metering) protocol for smart meter communication.

[![Go Version](https://img.shields.io/badge/go-1.25-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)

## Overview

libdlms-go provides a complete, production-ready implementation of the DLMS/COSEM protocol stack, enabling communication with smart electricity, gas, and water meters. This library implements the IEC 62056 (DLMS/COSEM) standards and supports various transport layers and security mechanisms.

### Features

- **Complete Protocol Stack**
  - DLMS Application Layer (both LN and SN referencing)
  - HDLC (High-Level Data Link Control) transport
  - TCP/IP with Wrapper protocol
  - RFC 2217 (Telnet) for serial-over-IP

- **Security & Authentication**
  - Multiple authentication mechanisms (None, Low, High-Level Security)
  - AES-GCM encryption (128/192/256-bit keys)
  - ECDSA digital signatures (P-256, P-384 curves)
  - SHA-256, SHA-384, GMAC authentication
  - Frame counter management

- **Advanced Features**
  - Block transfer for large datasets
  - Streaming data support
  - Profile generic objects (load profiles)
  - Selective access (time-based range queries)
  - V.44 data compression
  - Automatic retransmission and error recovery

- **Data Type Support**
  - All DLMS data types (integers, floats, strings, dates, arrays, structures)
  - OBIS code parsing and formatting
  - Type-safe data casting with reflection
  - DateTime with timezone support

## Installation

```bash
go get github.com/cybroslabs/libdlms-go
```

## Quick Start

### Basic Connection with Low-Level Authentication

```go
package main

import (
    "fmt"
    "time"

    "github.com/cybroslabs/libdlms-go/dlmsal"
    "github.com/cybroslabs/libdlms-go/tcp"
    "github.com/cybroslabs/libdlms-go/wrapper"
)

func main() {
    // Create DLMS settings with password authentication
    settings, _ := dlmsal.NewSettingsWithLowAuthenticationLN("password123")

    // Create TCP transport
    transport := tcp.New("192.168.1.100", 4059, 30*time.Second)

    // Wrap with DLMS wrapper protocol
    wrapperTransport, _ := wrapper.New(transport, 1, 1)

    // Create DLMS client
    client := dlmsal.New(wrapperTransport, settings)

    // Open connection
    if err := client.Open(); err != nil {
        panic(err)
    }
    defer client.Close()

    // Read active energy (OBIS 1-0:1.8.0.255)
    items := []dlmsal.DlmsLNRequestItem{{
        ClassId:   3,  // Register class
        Obis:      dlmsal.DlmsObis{A: 1, B: 0, C: 1, D: 8, E: 0, F: 255},
        Attribute: 2,  // Value attribute
    }}

    data, err := client.Get(items)
    if err != nil {
        panic(err)
    }

    // Cast to native type
    var value float64
    dlmsal.Cast(&value, data[0])
    fmt.Printf("Active Energy: %.2f kWh\n", value)
}
```

### HDLC Transport

```go
import "github.com/cybroslabs/libdlms-go/hdlc"

// Create HDLC settings
hdlcSettings := &hdlc.Settings{
    Logical:         1,
    Physical:        1,
    Client:          16,
    MaxRcv:          2048,
    MaxSnd:          2048,
    SnrmRetransmits: 3,
    Retransmits:     3,
}

// Wrap TCP with HDLC
hdlcTransport, _ := hdlc.New(tcpTransport, hdlcSettings)

// Use with DLMS client
client := dlmsal.New(hdlcTransport, dlmsSettings)
```

### High-Level Security with AES-GCM

```go
import "github.com/cybroslabs/libdlms-go/ciphering"

// Setup encryption
cipherSettings := &ciphering.CipheringSettings{
    EncryptionKey:             []byte{0x00, 0x01, ...}, // 16/24/32 bytes
    AuthenticationKey:         []byte{0x10, 0x11, ...},
    ClientTitle:               []byte{0x43, 0x42, ...}, // 8 bytes
    AuthenticationMechanismId: base.AuthenticationHighGmac,
}

cipher, _ := ciphering.NewNist(cipherSettings)

// Generate challenge-to-send
ctos := ciphering.GenerateCtoS(16)

// Create settings with encryption
settings, _ := dlmsal.NewSettingsWithCipheringLN(
    systemTitle,
    cipher,
    ctos,
    1, // Initial frame counter
    base.AuthenticationHighGmac,
)
```

### Reading Load Profile (Profile Generic)

```go
// Define time range
from := dlmsal.NewDlmsDateTimeFromTime(time.Now().Add(-24 * time.Hour))
to := dlmsal.NewDlmsDateTimeFromTime(time.Now())

// Create range access parameter
rangeAccess := dlmsal.EncodeSimpleRangeAccess(&from, &to)

// Request load profile
items := []dlmsal.DlmsLNRequestItem{{
    ClassId:          7, // Profile Generic
    Obis:             dlmsal.DlmsObis{A: 1, B: 0, C: 99, D: 1, E: 0, F: 255},
    Attribute:        2, // buffer
    HasAccess:        true,
    AccessDescriptor: 1, // Range descriptor
    AccessData:       &rangeAccess,
}}

data, err := client.Get(items)

// Parse load profile entries
var entries []ProfileEntry
dlmsal.Cast(&entries, data[0])
```

### Streaming Large Datasets

```go
// For very large profiles, use streaming
item := dlmsal.DlmsLNRequestItem{
    ClassId:   7,
    Obis:      dlmsal.DlmsObis{A: 1, B: 0, C: 99, D: 1, E: 0, F: 255},
    Attribute: 2,
}

stream, err := client.GetStream(item, false) // false = don't load in memory
if err != nil {
    panic(err)
}
defer stream.Close()

// Read data in chunks
for {
    data, err := stream.Read()
    if err == io.EOF {
        break
    }
    // Process data chunk
}
```

## Architecture

The library is organized into several packages:

### Core Packages

- **`dlmsal`** - DLMS Application Layer
  - Protocol implementation (AARQ/AARE, GET/SET/ACTION)
  - Data encoding/decoding
  - Client interface
  - Type conversions

- **`hdlc`** - HDLC Transport Layer
  - Frame transmission with CRC
  - Flow control and retransmission
  - SNRM negotiation

- **`tcp`** - TCP/IP Transport
  - Buffered TCP connection
  - Timeout and deadline management

- **`wrapper`** - DLMS Wrapper Protocol
  - Simple framing for TCP
  - Alternative to HDLC

- **`ciphering`** - Security & Encryption
  - AES-GCM encryption
  - ECDSA signatures
  - Authentication mechanisms
  - Streaming encryption

### Supporting Packages

- **`base`** - Common types and interfaces
- **`llc`** - Logical Link Control
- **`rfc2217`** - Telnet serial port protocol
- **`v44`** - V.44 data compression

## API Documentation

### DlmsClient Interface

```go
type DlmsClient interface {
    // Connection management
    Open() error
    Close() error
    Disconnect() error

    // Logical Name (LN) operations
    Get(items []DlmsLNRequestItem) ([]DlmsData, error)
    GetStream(item DlmsLNRequestItem, inmem bool) (DlmsDataStream, error)
    Set(items []DlmsLNRequestItem) ([]DlmsResultTag, error)
    Action(item DlmsLNRequestItem) (*DlmsData, error)
    LNAuthentication(checkresp bool) error

    // Short Name (SN) operations
    Read(items []DlmsSNRequestItem) ([]DlmsData, error)
    ReadStream(item DlmsSNRequestItem, inmem bool) (DlmsDataStream, error)
    Write(items []DlmsSNRequestItem) ([]DlmsResultTag, error)

    // Utilities
    SetLogger(logger *zap.SugaredLogger)
}
```

### OBIS Codes

OBIS codes identify data objects in DLMS. The library provides helpers:

```go
// Parse from string
obis, _ := dlmsal.NewDlmsObisFromString("1-0:1.8.0.255")

// Create programmatically
obis := dlmsal.DlmsObis{A: 1, B: 0, C: 1, D: 8, E: 0, F: 255}

// Format as string
str := obis.String() // "1-0:1.8.0.255"
```

### Data Type Casting

The `Cast` function provides type-safe conversion:

```go
var intValue int64
dlmsal.Cast(&intValue, data)

var timeValue time.Time
dlmsal.Cast(&timeValue, data)

var arrayValue []float64
dlmsal.Cast(&arrayValue, data)

type CustomStruct struct {
    Timestamp time.Time
    Value     float64
    Unit      uint8
}
var custom CustomStruct
dlmsal.Cast(&custom, data)
```

## Common OBIS Codes

| OBIS Code | Description |
|-----------|-------------|
| 1-0:1.8.0.255 | Active energy import (+A) |
| 1-0:2.8.0.255 | Active energy export (-A) |
| 1-0:3.8.0.255 | Reactive energy import (+R) |
| 1-0:4.8.0.255 | Reactive energy export (-R) |
| 1-0:1.7.0.255 | Active power import |
| 1-0:14.7.0.255 | Supply frequency |
| 1-0:32.7.0.255 | Voltage L1 |
| 1-0:52.7.0.255 | Voltage L2 |
| 1-0:72.7.0.255 | Voltage L3 |
| 1-0:31.7.0.255 | Current L1 |
| 1-0:51.7.0.255 | Current L2 |
| 1-0:71.7.0.255 | Current L3 |
| 0-0:96.1.0.255 | Meter serial number |
| 1-0:0.9.1.255 | Clock/time |
| 1-0:99.1.0.255 | Load profile 1 |

## Testing

Run the test suite:

```bash
go test ./...
```

Run with race detection:

```bash
go test -race ./...
```

## Performance Considerations

- **Streaming**: Use `GetStream` for large datasets to avoid memory issues
- **Block Transfer**: Automatically handled for data >PDU size
- **Connection Pooling**: Reuse connections when possible
- **Timeouts**: Set appropriate timeouts based on network conditions
- **Logging**: Disable verbose logging in production

## Protocol References

- IEC 62056-46: DLMS/COSEM HDLC data link layer
- IEC 62056-53: COSEM application layer
- IEC 62056-62: Interface classes
- IEC 62056-5-3: DLMS/COSEM application layer (Blue Book)

## Security Considerations

- **Never hardcode credentials** - use environment variables or secure vaults
- **Protect encryption keys** - use proper key management systems
- **Rotate frame counters** - prevent replay attacks
- **Validate certificates** - for ECDSA authentication
- **Use secure transport** - TLS for TCP connections when possible
- **Audit logging** - log authentication attempts and failures

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

Copyright (c) 2024 dDash s.r.o. All Rights Reserved.

This software is proprietary and confidential. It is owned by dDash s.r.o., Czechia, and is licensed for internal use only. Unauthorized copying, distribution, modification, or use of this software is strictly prohibited.

**dDash s.r.o.**
Strakonicka 3367
Smichov, 150 00 Prague
Czechia

Company ID: 06305741
TIN: CZ06305741

See the LICENSE file for complete terms and conditions.

## Support

For issues, questions, or contributions, please use the GitHub issue tracker.

## Acknowledgments

This implementation is based on the IEC 62056 (DLMS/COSEM) standards published by the International Electrotechnical Commission.
