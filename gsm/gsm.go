package gsm

import (
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"go.uber.org/zap"
)

const (
	cr              = 0xD
	lf              = 0xA
	_ok             = "^OK(?:\\s+.*)?$"
	_err            = "^ERROR(?:\\s+.*)?$"
	_maxlinelength  = 1024
	_maxresultlines = 128
)

type GsmCommand struct {
	Command      string
	OkAnswerRex  string
	BadAnswerRex string
}

type GsmSettings struct {
	DialCommand         string
	HangUpCommand       string
	InitCommands        []GsmCommand
	Escape              string
	EscapePause         time.Duration
	DialTimeout         time.Duration
	ModemCommandTimeout time.Duration
	DataTimeout         time.Duration
	InitPause           time.Duration
	AfterConnectPause   time.Duration
	ConnectOk           string
	ConnectFailed       string
}

func DefaultSettings() GsmSettings {
	return GsmSettings{
		DialCommand:   "ATDT",
		HangUpCommand: "ATH",
		InitCommands: []GsmCommand{
			{Command: "ATH", OkAnswerRex: _ok, BadAnswerRex: _err},
			{Command: "ATI", OkAnswerRex: _ok, BadAnswerRex: _err},
			{Command: "AT&F", OkAnswerRex: _ok, BadAnswerRex: _err},
			{Command: "ATE0", OkAnswerRex: _ok, BadAnswerRex: _err},
		},
		Escape:              "+++",
		EscapePause:         1500 * time.Millisecond,
		DialTimeout:         60000 * time.Millisecond,
		ModemCommandTimeout: 2500 * time.Millisecond,
		DataTimeout:         30000 * time.Millisecond,
		InitPause:           1500 * time.Millisecond,
		ConnectOk:           "^CONNECT(?:\\s+.*)?$",
		ConnectFailed:       "^(?:NO CARRIER|NO ANSWER|ERROR|BUSY)(?:\\s+.*)?$",
		AfterConnectPause:   1500 * time.Millisecond,
	}
}

type gsm struct {
	transport   base.SerialStream
	isopen      bool
	isconnected bool
	number      string
	settings    GsmSettings

	logger *zap.SugaredLogger
}

func New(number string, t base.SerialStream, settings *GsmSettings) base.Stream {
	ret := &gsm{
		number:    number,
		transport: t,
		settings:  *settings,
		isopen:    false,
	}
	return ret
}

func (r *gsm) logf(format string, v ...any) {
	if r.logger != nil {
		r.logger.Infof(format, v...)
	}
}

// Close implements base.Stream.
func (g *gsm) Close() error {
	return nil
}

func (g *gsm) hangup() error {
	if !g.isconnected {
		return nil
	}
	g.isconnected = false

	// hang itself here, but at least try to set dtr to false
	defer func() {
		err := g.transport.SetDTR(false)
		if err != nil { // bad
			g.logf("error setting DTR: %v", err)
		}
	}()

	g.logf("hanging up...")
	time.Sleep(g.settings.EscapePause)
	err := g.transport.Write([]byte(g.settings.Escape))
	if err != nil {
		return err
	}
	time.Sleep(g.settings.EscapePause)
	g.transport.SetTimeout(g.settings.ModemCommandTimeout)
	_, err = g.parseAnswerLines(GsmCommand{OkAnswerRex: _ok, BadAnswerRex: _err})
	if err != nil {
		g.logf("error hanging up (but ignoring): %v", err)
	}
	for ii := 0; ii < 3; ii++ {
		err = g.sendCommand(GsmCommand{Command: g.settings.HangUpCommand, OkAnswerRex: _ok, BadAnswerRex: _err})
		if err != nil {
			g.logf("error hanging up (but ignoring): %v", err)
		} else {
			return nil
		}
	}
	return fmt.Errorf("unable to properly hangup")
}

// Disconnect implements base.Stream.
func (g *gsm) Disconnect() error { // reall modem hangup
	if !g.isopen {
		return nil
	}
	g.isopen = false

	// hang itself here, but at least try to set dtr to false
	err := g.hangup()
	if err != nil {
		return err
	}
	return g.transport.Disconnect()
}

// GetRxTxBytes implements base.Stream.
func (g *gsm) GetRxTxBytes() (int64, int64) {
	return g.transport.GetRxTxBytes()
}

func (g *gsm) sendCommand(cmd GsmCommand) error {
	g.logf("send cmd: %s", cmd.Command)
	atb := append([]byte(cmd.Command), cr)
	err := g.transport.Write(atb)
	if err != nil {
		return err
	}
	res, err := g.parseAnswerLines(cmd)
	if err != nil {
		return err
	}
	if !res {
		return fmt.Errorf("bad answer")
	}
	return nil
}

func (g *gsm) readLine() (string, error) {
	var b [2]byte
	var ret []byte

	_, err := io.ReadFull(g.transport, b[:]) // i guess this has to be configurable, highly unlikely that all modems behave like that
	if err != nil {
		return "", err
	}
	b[0] &= 0x7f
	b[1] &= 0x7f
	if b[0] != cr || b[1] != lf {
		return "", fmt.Errorf("invalid line start")
	}
	for len(ret) < _maxlinelength {
		_, err = io.ReadFull(g.transport, b[:1])
		if err != nil {
			return "", err
		}
		b[0] &= 0x7f
		if b[0] == lf {
			if len(ret) == 0 {
				return "", fmt.Errorf("no carriage return, invalid line")
			}
			if ret[len(ret)-1] != cr {
				return "", fmt.Errorf("no carriage return, invalid line")
			}
			return string(ret[:len(ret)-1]), nil
		}
		ret = append(ret, b[0])
	}
	return "", fmt.Errorf("line too long")
}

func (g *gsm) parseAnswerLines(cmd GsmCommand) (bool, error) {
	// so according to doc, every info unit should be bracketed with CR LF, well... let's parse it including these empty lines between units till there is either ok or error
	cnt := 0
	for cnt < _maxresultlines {
		l, err := g.readLine()
		if err != nil {
			return false, err
		}
		g.logf("received line: %s", l)
		// try some regex for both answer types
		b, err := regexp.MatchString(cmd.OkAnswerRex, l)
		if err != nil {
			return false, err
		}
		if b {
			return true, nil
		}
		if len(cmd.BadAnswerRex) > 0 {
			b, err = regexp.MatchString(cmd.BadAnswerRex, l)
			if err != nil {
				return false, err
			}
			if b {
				return false, nil
			}
		}
		cnt++
	}
	return false, fmt.Errorf("too many lines received")
}

func (g *gsm) startInit() error {
	ok := GsmCommand{Command: "AT", OkAnswerRex: "^OK$", BadAnswerRex: "^ERROR$"}
	for ii := 0; ii < 3; ii++ {
		err := g.sendCommand(ok)
		if err == nil {
			return nil
		}
		time.Sleep(g.settings.InitPause)
	}
	return fmt.Errorf("modem not responding")
}

// Open implements base.Stream.
func (g *gsm) Open() error {
	if g.isopen { // a bit controversal
		return nil
	}

	if err := g.transport.Open(); err != nil {
		return err
	}
	g.isopen = true

	if err := g.transport.SetDTR(true); err != nil {
		return err
	}

	g.transport.SetTimeout(g.settings.ModemCommandTimeout)
	err := g.startInit()
	if err != nil {
		return err
	}

	for _, cmd := range g.settings.InitCommands {
		err := g.sendCommand(cmd)
		if err != nil {
			return err
		}
	}

	g.transport.SetTimeout(g.settings.DialTimeout)
	err = g.sendCommand(GsmCommand{
		Command:      g.settings.DialCommand + g.number,
		OkAnswerRex:  g.settings.ConnectOk,
		BadAnswerRex: g.settings.ConnectFailed,
	})
	if err != nil {
		g.logf("error dialing: %v", err)
		return err
	}
	time.Sleep(g.settings.AfterConnectPause)
	g.transport.SetTimeout(g.settings.DataTimeout)
	g.isconnected = true
	return nil
}

// Read implements base.Stream.
func (g *gsm) Read(p []byte) (n int, err error) {
	if !g.isconnected {
		return 0, base.ErrNotOpened
	}
	return g.transport.Read(p)
}

func (g *gsm) SetTimeout(t time.Duration) {
	g.transport.SetTimeout(t)
}

// SetDeadline implements base.Stream.
func (g *gsm) SetDeadline(t time.Time) {
	g.transport.SetDeadline(t)
}

// SetLogger implements base.Stream.
func (g *gsm) SetLogger(logger *zap.SugaredLogger) {
	g.logger = logger
	g.transport.SetLogger(logger)
}

// SetMaxReceivedBytes implements base.Stream.
func (g *gsm) SetMaxReceivedBytes(m int64) {
	g.transport.SetMaxReceivedBytes(m)
}

// Write implements base.Stream.
func (g *gsm) Write(src []byte) error {
	if !g.isconnected {
		return base.ErrNotOpened
	}
	return g.transport.Write(src)
}
