package base

import "errors"

var ErrNothingToRead = errors.New("nothing to read")
var ErrNotOpened = errors.New("connection is not open")
var ErrCommunicationTimeout = errors.New("communication timeout")
