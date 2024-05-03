package base

import (
	"time"

	"go.uber.org/zap"
)

type Stream interface { // todo, make it a bit more streamable, so receive wanted amount of bytes with guaranted amount or timeout or error...
	Close() error
	Open() error
	Disconnect() error // hard end of connection without solving any unassociation or so
	IsOpen() bool
	SetLogger(logger *zap.SugaredLogger)
	SetDeadline(t time.Time)     // zero time means no deadline
	SetMaxReceivedBytes(m int64) // every call resets current counter, exceeding bytes count means comm error, only incomming bytes are counted
	Read(p []byte) (n int, err error)
	Write(src []byte) error // always write everything
}
