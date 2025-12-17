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
	// Moxa Real COM protocol uses TWO separate TCP connections:
	// 1. Data stream - for serial data transmission
	// 2. Command stream - for ASPP control commands
	//
	// Both connections typically use the same port on the Moxa device
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
