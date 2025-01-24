package hdlc

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"go.uber.org/zap"
)

const (
	maxBytesBefore7e = 100
	maxLength        = 2050
	maxPackets       = 20
	maxBody          = 10000000
	initpacketlength = 2000
	maxRRframecycles = 10
	maxEmptycycles   = 10
	maxReadoutBytes  = 1000000
)

type maclayer struct {
	transport      base.Stream
	logical        uint16
	physical       uint16
	client         byte
	logger         *zap.SugaredLogger
	recvbuffer     [maxLength]byte
	sendbuffer     [maxLength]byte
	maxrcv         uint
	maxsnd         uint
	isopen         bool
	controlS       byte
	controlR       byte
	tosend         int
	state          int // 0 - start, 1 - writting, 2 - reading
	packetsbuffer  [maxPackets]macpacket
	toberead       []macpacket
	tobereadpacket *macpacket
	emptyframes    int
	canwrite       bool // controling final/poll bit
}

type macpacket struct {
	control      byte
	info         []byte
	segmented    bool
	inlinelength int // ok, rely on default 0 value for this, in case some value, it is inlined already in sndbuffer, a bit hardcore
}

type Settings struct {
	Logical  uint16
	Physical uint16
	Client   byte
	MaxRcv   uint
	MaxSnd   uint
}

func New(transport base.Stream, settings *Settings) (base.Stream, error) {
	if settings.Logical > 0x3fff {
		return nil, fmt.Errorf("invalid logical address")
	}
	if settings.Physical > 0x3fff {
		return nil, fmt.Errorf("invalid physical address")
	}
	if settings.Client > 0x7f {
		return nil, fmt.Errorf("invalid client address")
	}
	if settings.MaxRcv > initpacketlength {
		settings.MaxRcv = initpacketlength
	} else if settings.MaxRcv < 128 {
		settings.MaxRcv = 128
	}
	if settings.MaxSnd > initpacketlength {
		settings.MaxSnd = initpacketlength
	} else if settings.MaxSnd < 128 {
		settings.MaxSnd = 128
	}

	w := &maclayer{
		transport:      transport,
		logical:        settings.Logical,  // upper
		physical:       settings.Physical, // lower
		client:         settings.Client,
		logger:         nil,
		maxrcv:         settings.MaxRcv,
		maxsnd:         settings.MaxSnd,
		isopen:         false,
		controlS:       0,
		controlR:       0,
		tosend:         0,
		state:          0,
		toberead:       nil,
		tobereadpacket: nil,
		emptyframes:    0,
		canwrite:       true,
	}
	return w, nil
}

func (w *maclayer) logf(format string, v ...any) {
	if w.logger != nil {
		w.logger.Infof(format, v...)
	}
}

func (w *maclayer) Close() error {
	if !w.isopen {
		return nil
	}
	err := w.readout()
	if err != nil {
		return err
	}
	// try to send RR just like that? ;), put that behind some configuration maybe
	{
		err = w.writepacket(macpacket{control: (w.controlR << 5) | 1, info: nil, segmented: false}, true)
		if err != nil {
			return err
		}
		err = w.processRRresp()
		if err != nil {
			return err
		}
	}

	// send even disconnect
	err = w.writepacket(macpacket{control: 0x43, info: nil, segmented: false}, true)
	if err != nil {
		return fmt.Errorf("unable to create disconnect packet")
	}
	_, err = w.readpackets() // just ignoring whatever returns
	if err != nil {
		return err
	}

	w.isopen = false
	return w.transport.Close()
}

func (w *maclayer) Open() error {
	if w.isopen {
		return nil
	}
	if err := w.transport.Open(); err != nil {
		return err
	}
	// snrm here, always negotiate for now
	p := w.recvbuffer[:0]
	if w.maxrcv > 128 || w.maxsnd > 128 { // longer snrm
		p = append(p, 0x81, 0x80, 0x14, 0x05, 0x02, byte(w.maxsnd>>8), byte(w.maxsnd), 0x06, 0x02, byte(w.maxrcv>>8), byte(w.maxrcv))
	} else {
		p = append(p, 0x81, 0x80, 0x14, 0x05, 0x01, byte(w.maxsnd), 0x06, 0x01, byte(w.maxrcv))
	}
	p = append(p, 0x07, 0x04, 0x00, 0x00, 0x00, 0x01, 0x08, 0x04, 0x00, 0x00, 0x00, 0x01)

	err := w.writepacket(macpacket{control: 0x83, info: p, segmented: false}, true)
	if err != nil {
		return err
	}
	// receive and parse snrm response
	r, err := w.readpackets()
	if err != nil {
		return err
	}
	if len(r) == 0 {
		return fmt.Errorf("no packet received, EOF?")
	}
	if len(r) > 1 {
		return fmt.Errorf("more than one packet received, expecting only one as snrm answer")
	}

	if r[0].control != 0x63 {
		return fmt.Errorf("invalid snrm answer, expected UA, got %x", r[0].control)
	}
	err = w.parsesnrmua(r[0].info)
	if err != nil {
		return err
	}
	w.logf("snrm completed, having maxsnd: %v, maxrcv: %v", w.maxsnd, w.maxrcv)

	w.isopen = true
	return nil
}

func (w *maclayer) parsesnrmua(ua []byte) error {
	if ua == nil {
		return fmt.Errorf("no ua response")
	}
	if len(ua) < 21 {
		return fmt.Errorf("too short snrm response")
	}
	if ua[0] != 0x81 || ua[1] != 0x80 {
		return fmt.Errorf("invalid snrm response header")
	}
	if len(ua) != int(ua[2])+3 {
		return fmt.Errorf("invalid snrm response length")
	}
	for i := 3; i < len(ua); i++ {
		con, t, err := readsnrmuatag(ua[i+1:])
		if err != nil {
			return err
		}
		switch ua[i] {
		case 5:
			if t < w.maxrcv {
				w.maxrcv = t
			}
		case 6:
			if t < w.maxsnd {
				w.maxsnd = t
			}
		case 7: // windows always 1 for now
		case 8:
		default:
			return fmt.Errorf("invalid snrm response tag: %v", ua[i])
		}
		i += con
	}
	return nil
}

func readsnrmuatag(t []byte) (int, uint, error) {
	if len(t) < 2 {
		return 0, 0, fmt.Errorf("too short tag")
	}
	switch t[0] {
	case 1:
		return 2, uint(t[1]), nil
	case 2:
		if len(t) < 3 {
			return 0, 0, fmt.Errorf("too short tag")
		}
		return 3, (uint(t[1]) << 8) | uint(t[2]), nil
	case 4:
		if len(t) < 5 {
			return 0, 0, fmt.Errorf("too short tag")
		}
		return 5, (uint(t[1]) << 24) | (uint(t[2]) << 16) | (uint(t[3]) << 8) | uint(t[4]), nil
	default:
		return 0, 0, fmt.Errorf("invalid tag length")
	}
}

func (w *maclayer) Disconnect() error {
	w.isopen = false // just hardcore
	return w.transport.Disconnect()
}

func (w *maclayer) getnextI() (pck *macpacket, err error) {
	for len(w.toberead) > 0 {
		pck = &w.toberead[0]
		w.toberead = w.toberead[1:]
		if pck.control&1 == 0 { // I frame
			if pck.control>>5 != w.controlS { // handling retransmittion here, that would be fun
				return nil, fmt.Errorf("invalid unexpected packet numbering (RRR)")
			}
			if (pck.control>>1)&7 != w.controlR {
				return nil, fmt.Errorf("invalid unexpected packet numbering (SSS)")
			}
			w.controlR = (w.controlR + 1) & 7
			return
		} else if pck.control == 3 {
			w.logf("received UI, discarding")
		} else if pck.control&0xf == 1 {
			if pck.control>>5 != w.controlS {
				return nil, fmt.Errorf("invalid unexpected packet numbering (RRR)")
			}
		} else {
			return nil, fmt.Errorf("unexpected frame type %x", pck.control)
		}
	}
	return nil, nil
}

func (w *maclayer) sendRR() error {
	return w.writepacket(macpacket{control: (w.controlR << 5) | 1, info: nil, segmented: false}, true)
}

func (w *maclayer) Read(p []byte) (n int, err error) {
	if !w.isopen {
		return 0, base.ErrNotOpened
	}
	if w.state == 0 {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, base.ErrNothingToRead
	}
	err = w.writeout()
	if err != nil {
		return 0, err
	}
	// check if there is something to readout
	if w.tobereadpacket != nil { // something in last packet, readout that...
		if len(w.tobereadpacket.info) == 0 { // readout everything, decide according to segmentation what to do next
			w.emptyframes--
			if w.emptyframes <= 0 {
				return 0, fmt.Errorf("too many empty frames")
			}
			next, err := w.getnextI()
			if err != nil {
				return 0, err
			}
			if next == nil { // check segmentation, otherwise set state and return EOF
				if w.tobereadpacket.segmented { // ask for another packets
					err = w.sendRR()
					if err != nil {
						return 0, err
					}
					w.tobereadpacket = nil
				} else {
					w.state = 0
					w.tobereadpacket = nil
					return 0, io.EOF
				}
			} else {
				w.tobereadpacket = next
				return w.Read(p) // recursion, hooray, max window size, so this is ok (max received packets is 20 anyway, or something like that)
			}
		} else {
			w.emptyframes = maxEmptycycles
			n = copy(p, w.tobereadpacket.info)
			w.tobereadpacket.info = w.tobereadpacket.info[n:]
			return n, nil
		}
	}

	for bcnt := maxRRframecycles; bcnt > 0; bcnt-- {
		w.toberead, err = w.readpackets()
		if err != nil {
			return 0, err
		}
		w.tobereadpacket, err = w.getnextI()
		if err != nil {
			return 0, err
		}
		if w.tobereadpacket != nil {
			return w.Read(p)
		}
		err = w.sendRR()
		if err != nil {
			return 0, err
		}
	}
	return 0, fmt.Errorf("too many RR received")
}

func (w *maclayer) nextcontrol() byte {
	r := (w.controlR << 5) | (w.controlS << 1)
	w.controlS = (w.controlS + 1) & 7
	return r
}

func (w *maclayer) processRRresp() error {
	r, err := w.readpackets()
	if err != nil {
		return err
	}
	if len(r) == 0 {
		return fmt.Errorf("no packet received, EOF?")
	}
	// at least some RR is expected, and ONLY RR, because inside segmented I frame there should be only RR (i hope)
	hasRR := false
	for _, p := range r {
		if p.control&1 == 0 {
			return fmt.Errorf("unexpected I frame, not good")
		}
		if p.control == 3 {
			w.logf("received UI, discarding")
		} else if p.control&0xf == 1 {
			if hasRR {
				return fmt.Errorf("duplicit RR received")
			}
			hasRR = true
			if p.control>>5 != w.controlS {
				return fmt.Errorf("invalid RRR numbering (repetition not yet supported)")
			}
		} else {
			return fmt.Errorf("unexpected frame type %x", p.control)
		}
	}
	// clear references? max bytes is about packets * 2kB, so 40kB in default
	if !hasRR {
		return fmt.Errorf("no RR received")
	}
	return nil
}

func (w *maclayer) Write(src []byte) error {
	if !w.isopen {
		return base.ErrNotOpened
	}
	if len(src) == 0 {
		return nil
	}
	// readout pending things, use general Read till eof, no other way damn it, use rcvbuffer as only first 3 bytes are used, this is a bit hell
	err := w.readout()
	if err != nil {
		return err
	}
	// fuck, as write is supposed to process everything, this has to be cycle
	for len(src) > 0 {
		l := len(src)
		s := false
		if w.tosend+l > int(w.maxsnd) {
			l = int(w.maxsnd) - w.tosend
			s = true
		}
		copy(w.sendbuffer[w.tosend+11:], src[:l])
		w.tosend += l
		if s { // send partial packet with segment bit
			err = w.writepacket(macpacket{control: w.nextcontrol(), inlinelength: w.tosend, segmented: true}, true)
			if err != nil {
				return err
			}
			// expecting RR after final bit but during segmented transfer
			err = w.processRRresp()
			if err != nil {
				return err
			}
			w.tosend = 0
		}
		src = src[l:]
	}
	return nil
}

func (w *maclayer) writeout() error {
	if w.tosend > 0 { // last packet wasnt sent, so send it
		err := w.writepacket(macpacket{control: w.nextcontrol(), inlinelength: w.tosend, segmented: false}, true)
		if err != nil {
			return err
		}
		w.tosend = 0
	}
	if w.state != 2 {
		w.toberead = nil
		w.tobereadpacket = nil
		w.emptyframes = maxEmptycycles
		w.state = 2
	}
	return nil
}

func (w *maclayer) readout() error {
	switch w.state {
	case 0: // at the very beginning, do nothing
		w.tosend = 0
		w.state = 1
		return nil
	case 1: // in the middle of writting, do nothing, so adfter calling from Close, this could lead to error, but i dont care
		return nil
	}
	// ok, using sndbuffer for receiving, because is not used during creating packet stream and i dont care about content
	bcnt := maxReadoutBytes
	for {
		n, err := w.Read(w.sendbuffer[:])
		bcnt -= n
		if err != nil {
			if errors.Is(err, io.EOF) {
				w.tosend = 0
				w.state = 1
				return nil
			}
			return err
		}
		if bcnt <= 0 {
			return fmt.Errorf("too many bytes read")
		}
	}
}

func (w *maclayer) SetMaxReceivedBytes(m int64) {
	w.transport.SetMaxReceivedBytes(m)
}

func (w *maclayer) SetDeadline(t time.Time) {
	w.transport.SetDeadline(t)
}

func (w *maclayer) SetLogger(logger *zap.SugaredLogger) {
	w.logger = logger
	w.transport.SetLogger(logger)
}

func (w *maclayer) GetRxTxBytes() (int64, int64) {
	return w.transport.GetRxTxBytes()
}

var fcstab = [...]uint16{
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78,
}

func mac_crc16(d []byte) uint16 {
	c := uint16(0xffff)
	for _, b := range d {
		c = fcstab[byte(c)^b] ^ (c >> 8)
	}
	return c ^ 0xffff
}

func mac_crc16_r(d []byte, ih int) (hcs uint16, fcs uint16) {
	c := uint16(0xffff)
	for i := 0; i < ih; i++ {
		c = fcstab[byte(c)^d[i]] ^ (c >> 8)
	}
	hcs = c ^ 0xffff
	for i := ih; i < len(d); i++ {
		c = fcstab[byte(c)^d[i]] ^ (c >> 8)
	}
	return hcs, c ^ 0xffff
}

// receive series of whole mac packets, no other way, from segmented tcp streaming, using rcvbuffer for first packet, extra memory for the rest
func (w *maclayer) readpackets() ([]macpacket, error) {
	if w.canwrite {
		return nil, fmt.Errorf("cannot read packets, write is expected")
	}

	off := 0
	first := true
	final := false
	for !final {
		if off >= len(w.packetsbuffer) {
			return nil, fmt.Errorf("too many packets received")
		}
		m, err := w.readpacket(first)
		if err != nil {
			return nil, err
		}
		first = false
		final = m.control&0x10 != 0
		m.control &= 0xef // clear final bit
		w.packetsbuffer[off] = m
		off++
	}
	w.canwrite = true
	return w.packetsbuffer[:off], nil // everything is received, final is set, our turn now
}

func (w *maclayer) parseminheader() (uint, error) {
	if (w.recvbuffer[1] & 0xf0) != 0xa0 {
		return 0, fmt.Errorf("invalid starting packet: %X", w.recvbuffer[1])
	}
	length := ((uint(w.recvbuffer[1]) & 7) << 8) | uint(w.recvbuffer[2])
	if length < 7 {
		return 0, fmt.Errorf("invalid packet length, too short")
	}
	return length - 2, nil
}

func (w *maclayer) readpacket(first bool) (pck macpacket, err error) { // remove recursion and call it repeatedly from another caller and return array of packets
	// 0 waiting for 0x7e and reading minimal header, 1 reading rest of the packet, 2 closing 0x7e (maybe not so necessary)
	length := uint(0)
	if first {
		bcnt := 0
		for {
			_, err = io.ReadFull(w.transport, w.recvbuffer[:3])
			if err != nil {
				return
			}
			if w.recvbuffer[0] == 0x7e { // have minimal header already
				length, err = w.parseminheader()
				if err != nil {
					return
				}
				break
			}
			if w.recvbuffer[1] == 0x7e {
				w.recvbuffer[1] = w.recvbuffer[2]
				_, err = io.ReadFull(w.transport, w.recvbuffer[2:3]) // read one remaining header byte
				if err != nil {
					return
				}
				length, err = w.parseminheader()
				if err != nil {
					return
				}
				break
			}
			if w.recvbuffer[2] == 0x7e {
				_, err = io.ReadFull(w.transport, w.recvbuffer[1:3]) // read one remaining header byte
				if err != nil {
					return
				}
				length, err = w.parseminheader()
				if err != nil {
					return
				}
				break
			}
			bcnt += 3
			if bcnt > maxBytesBefore7e {
				return pck, fmt.Errorf("too many bytes before any 0x7e found")
			}
		}
	} else { // no searching, there has to be either 0x7e or 0xa0
		_, err = io.ReadFull(w.transport, w.recvbuffer[1:3])
		if err != nil {
			return
		}
		if (w.recvbuffer[1] & 0xf0) == 0xa0 {
			length, err = w.parseminheader()
			if err != nil {
				return
			}
		} else if w.recvbuffer[1] == 0x7e {
			w.recvbuffer[1] = w.recvbuffer[2]
			_, err = io.ReadFull(w.transport, w.recvbuffer[2:3]) // read one remaining header byte
			if err != nil {
				return
			}
			length, err = w.parseminheader()
			if err != nil {
				return
			}
		}
	}
	// reading the rest of the packet, in case of first packet VIOLATING consistency by reading that directly into rcvbuffer without doing make
	var pckinfo []byte
	if first {
		pckinfo = w.recvbuffer[1 : length+4] // this is hardcore
	} else {
		pckinfo = make([]byte, length+3)
	}
	_, err = io.ReadFull(w.transport, pckinfo[2:])
	if err != nil {
		return
	}
	if pckinfo[length+2] != 0x7e {
		return pck, fmt.Errorf("there is no closing tag found")
	}
	pckinfo[0] = w.recvbuffer[1] // min header
	pckinfo[1] = w.recvbuffer[2]
	return w.parsepacket(pckinfo[:length+2])
}

func (w *maclayer) parsepacket(ori []byte) (pck macpacket, err error) {
	if len(ori) < 6 {
		return pck, fmt.Errorf("too short packet")
	}

	// check addresses
	if ori[2]&1 == 0 {
		return pck, fmt.Errorf("invalid ending bit of client address")
	}
	if ori[2]>>1 != w.client {
		return pck, fmt.Errorf("invalid client address")
	}
	offset := 0
	var log uint16     // upper
	var phy uint16     // lower
	if ori[3]&1 != 0 { // single address
		log = uint16(ori[3] >> 1)
		phy = 0
		offset = 1
	} else if ori[4]&1 != 0 { // each single byte
		log = uint16(ori[3] >> 1)
		phy = uint16(ori[4] >> 1)
		offset = 2
	} else if ori[5]&1 != 0 {
		return pck, fmt.Errorf("invalid address field, premature termination bit")
	} else if len(ori) < 7 {
		return pck, fmt.Errorf("too short packet for whole address")
	} else if ori[6]&1 == 0 {
		return pck, fmt.Errorf("there is no termination bit in address field")
	} else {
		log = uint16(ori[3]>>1)<<7 | uint16(ori[4]>>1)
		phy = uint16(ori[5]>>1)<<7 | uint16(ori[6]>>1)
		offset = 4
	}

	if log != w.logical {
		return pck, fmt.Errorf("mismatch logical address")
	}
	if phy != w.physical {
		return pck, fmt.Errorf("mismatch physical address")
	}

	if len(ori) < offset+6 {
		return pck, fmt.Errorf("too short packet")
	}

	offset += 3
	pck.segmented = ori[0]&8 != 0
	pck.control = ori[offset]
	// now offset points to control byte, so determine packet type or something
	rem := len(ori) - offset
	switch {
	case rem < 3:
		return pck, fmt.Errorf("too short packet")
	case rem == 3: // just fcs and no info
		// check FCS
		fcs := mac_crc16(ori[:len(ori)-2])
		if fcs != uint16(ori[len(ori)-2])|(uint16(ori[len(ori)-1])<<8) {
			return pck, fmt.Errorf("fcs mismatch")
		}
		return pck, nil
	case rem == 4:
		return pck, fmt.Errorf("invalid packet length")
	default: // having some info
		hcs, fcs := mac_crc16_r(ori[:len(ori)-2], offset+1)
		if hcs != uint16(ori[offset+1])|(uint16(ori[offset+2])<<8) {
			return pck, fmt.Errorf("hcs mismatch")
		}
		if fcs != uint16(ori[len(ori)-2])|(uint16(ori[len(ori)-1])<<8) {
			return pck, fmt.Errorf("fcs mismatch")
		}
		pck.info = ori[offset+3 : len(ori)-2] // dont copy, keep slice so wasting memory for crc and header
	}

	return pck, nil
}

func (w *maclayer) getaddresslength() int {
	if w.logical <= 0x7f {
		if w.physical == 0 {
			return 1
		} else {
			if w.physical <= 0x7f {
				return 2
			}
		}
	}
	return 4
}

func mac_crc16_w(d []byte, ih int) uint16 {
	c := uint16(0xffff)
	for i := 0; i < ih; i++ {
		c = fcstab[byte(c)^d[i]] ^ (c >> 8)
	}
	hcs := c ^ 0xffff
	d[ih] = byte(hcs)
	d[ih+1] = byte(hcs >> 8)

	for i := ih; i < len(d); i++ {
		c = fcstab[byte(c)^d[i]] ^ (c >> 8)
	}
	return c ^ 0xffff
}

func (w *maclayer) writepacket(packet macpacket, final bool) (err error) {
	if !w.canwrite {
		return fmt.Errorf("cannot write right now")
	}

	addrlen := w.getaddresslength()

	var pck []byte
	switch addrlen {
	case 1:
		w.sendbuffer[6] = byte(w.logical<<1) | 1
		pck = w.sendbuffer[3:]
	case 2:
		w.sendbuffer[5] = byte(w.logical << 1)
		w.sendbuffer[6] = byte(w.physical<<1) | 1
		pck = w.sendbuffer[2:]
	case 4:
		w.sendbuffer[3] = byte(w.logical>>7) << 1
		w.sendbuffer[4] = byte(w.logical << 1)
		w.sendbuffer[5] = byte(w.physical>>7) << 1
		w.sendbuffer[6] = byte(w.physical<<1) | 1
		pck = w.sendbuffer[:]
	default:
		return fmt.Errorf("invalid address length, programatic error")
	}

	pck[0] = 0x7e
	offset := 3 + addrlen // address + header + 0x7e
	pck[offset] = byte(w.client<<1) | 1
	offset++
	pck[offset] = packet.control
	if final {
		pck[offset] |= 0x10
	}
	offset++
	ilen := packet.inlinelength
	pcopy := false
	if ilen == 0 {
		ilen = len(packet.info) // suitable even for nil, so who cares
		pcopy = true
	}
	if ilen > 0 {
		leni := offset + 3 + ilen
		if leni > 0x7ff {
			return fmt.Errorf("too long packet to encode")
		}
		pck[1] = 0xa0 | byte(leni>>8)
		if packet.segmented {
			pck[1] |= 8
		}
		pck[2] = byte(leni)
		offset += 2
		if pcopy {
			copy(pck[offset:], packet.info)
		}
		offset += ilen
		fcs := mac_crc16_w(pck[1:offset], offset-3-ilen)
		pck[offset] = byte(fcs)
		offset++
		pck[offset] = byte(fcs >> 8)
		offset++
	} else { // only single crc here (FCS)
		pck[1] = 0xa0
		if packet.segmented {
			pck[1] |= 8
		}
		pck[2] = byte(offset + 1)
		fcs := mac_crc16(pck[1:offset])
		pck[offset] = byte(fcs)
		offset++
		pck[offset] = byte(fcs >> 8)
		offset++
	}
	pck[offset] = 0x7e
	offset++

	w.canwrite = !final // no windowing yet
	return w.transport.Write(pck[:offset])
}
