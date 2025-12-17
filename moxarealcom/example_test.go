package moxarealcom_test

import (
	"fmt"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"github.com/cybroslabs/libdlms-go/moxarealcom"
	"github.com/cybroslabs/libdlms-go/tcp"
)

// Example demonstrates how to use the Moxa Real COM driver
func Example() {
	// Create TCP transport to connect to Moxa NPort device
	// Default Moxa Real COM uses ports 4001-4016 for data connections
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
		fmt.Printf("Failed to open: %v\n", err)
		return
	}
	defer func() { _ = serial.Disconnect() }()

	// Set timeout for read operations
	serial.SetTimeout(2 * time.Second)

	// Write data
	data := []byte("Hello, Moxa!\r\n")
	if err := serial.Write(data); err != nil {
		fmt.Printf("Failed to write: %v\n", err)
		return
	}

	// Read response
	buffer := make([]byte, 256)
	n, err := serial.Read(buffer)
	if err != nil {
		fmt.Printf("Failed to read: %v\n", err)
		return
	}

	fmt.Printf("Received %d bytes\n", n)

	// Change serial settings dynamically
	if err := serial.SetSpeed(115200, base.Serial8DataBits, base.SerialNoParity, base.SerialOneStopBit); err != nil {
		fmt.Printf("Failed to set speed: %v\n", err)
		return
	}

	// Control DTR line
	if err := serial.SetDTR(true); err != nil {
		fmt.Printf("Failed to set DTR: %v\n", err)
		return
	}
}
