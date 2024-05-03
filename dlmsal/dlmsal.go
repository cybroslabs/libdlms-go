package dlmsal

import (
	"bytes"
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
	"go.uber.org/zap"
)

const (
	DlmsVersion = 0x06

	VAANameLN = 0x0007
	VAANameSN = 0xFA00
)

type Authentication byte

const (
	AuthenticationNone       Authentication = 0 // No authentication is used.
	AuthenticationLow        Authentication = 1 // Low authentication is used.
	AuthenticationHigh       Authentication = 2 // High authentication is used.
	AuthenticationHighMD5    Authentication = 3 // High authentication is used. Password is hashed with MD5.
	AuthenticationHighSHA1   Authentication = 4 // High authentication is used. Password is hashed with SHA1.
	AuthenticationHighGmac   Authentication = 5 // High authentication is used. Password is hashed with GMAC.
	AuthenticationHighSha256 Authentication = 6 // High authentication is used. Password is hashed with SHA-256.
	AuthenticationHighEcdsa  Authentication = 7 // High authentication is used. Password is hashed with ECDSA.
)

type DlmsSNRequestItem struct {
	Address          int16
	HasAccess        bool
	AccessDescriptor byte
	AccessData       *DlmsData
	WriteData        *DlmsData
}

type DlmsLNRequestItem struct {
	ClassId          uint16
	Obis             DlmsObis
	Attribute        int8
	HasAccess        bool
	AccessDescriptor byte
	AccessData       *DlmsData
	SetData          *DlmsData
}

type DlmsClient interface {
	Close() error
	Disconnect() error
	IsOpen() bool
	Open() error
	SetLogger(logger *zap.SugaredLogger)
	Get(items []DlmsLNRequestItem) ([]DlmsData, error)
	Read(items []DlmsSNRequestItem) ([]DlmsData, error)
}

type dlmsal struct {
	transport      base.Stream
	logger         *zap.SugaredLogger
	settings       *DlmsSettings
	isopen         bool
	aareres        aareresponse
	maxPduSendSize int

	// things for communications
	invokeid  byte
	buffer    []byte
	tmpbuffer []byte
	pdu       bytes.Buffer // reused for sending requests
}

type DlmsSettings struct {
	Authentication     Authentication
	ApplicationContext ApplicationContext
	Password           []byte
	ConformanceBlock   uint32
	MaxPduRecvSize     int
	VAAddress          int16
	HighPriority       byte
	ConfirmedRequests  byte
}

func NewSettingsWithLowAuthenticationSN(password string) (*DlmsSettings, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password is empty")
	}
	return &DlmsSettings{
		Authentication:     AuthenticationLow,
		ApplicationContext: ApplicationContextSNNoCiphering,
		Password:           []byte(password),
		ConformanceBlock: ConformanceBlockBlockTransferWithGetOrRead | ConformanceBlockBlockTransferWithSetOrWrite |
			ConformanceBlockRead | ConformanceBlockWrite | ConformanceBlockSelectiveAccess | ConformanceBlockMultipleReferences,
	}, nil
}

func NewSettingsWithLowAuthenticationLN(password string) (*DlmsSettings, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password is empty")
	}
	return &DlmsSettings{
		Authentication:     AuthenticationLow,
		ApplicationContext: ApplicationContextLNNoCiphering,
		Password:           []byte(password),
		HighPriority:       0x80,
		ConfirmedRequests:  0x40,
		ConformanceBlock: ConformanceBlockBlockTransferWithGetOrRead | ConformanceBlockBlockTransferWithSetOrWrite |
			ConformanceBlockBlockTransferWithAction | ConformanceBlockAction | ConformanceBlockGet | ConformanceBlockSet |
			ConformanceBlockSelectiveAccess | ConformanceBlockMultipleReferences | ConformanceBlockAttribute0SupportedWithGet,
	}, nil
}

func New(transport base.Stream, settings *DlmsSettings) DlmsClient {
	return &dlmsal{
		transport: transport,
		logger:    nil,
		settings:  settings,
		isopen:    false,
		invokeid:  0,
		buffer:    make([]byte, 2048),
		tmpbuffer: make([]byte, 128), // temp storage for decoding length and so on, sure it could be allocated every time, but maximum possible reusable...
	}
}

func (w *dlmsal) logf(format string, v ...any) {
	if w.logger != nil {
		w.logger.Infof(format, v...)
	}
}

func (d *dlmsal) Close() error {
	if !d.isopen {
		return nil
	}

	rl, err := encodeRLRQ(d.settings)
	if err != nil {
		return err
	}
	err = d.transport.Write(rl)
	if err != nil {
		return err
	}
	_, err = d.smallreadout()
	d.isopen = false
	if err != nil { // just ignore data itself as simulator returns some weird shit (based on e650 maybe)
		return err
	}

	return nil
}

func (d *dlmsal) Disconnect() error {
	d.isopen = false
	return d.transport.Disconnect()
}

func (d *dlmsal) IsOpen() bool {
	return d.isopen
}

func (d *dlmsal) smallreadout() ([]byte, error) {
	// safely use already existing buffer, it could fail if aare is bigger than it, but it can be solved later
	total := 0
	for {
		if total == len(d.buffer) {
			return nil, fmt.Errorf("no room for aare or rlre")
		}
		n, err := d.transport.Read(d.buffer[total:])
		if err == io.EOF {
			return d.buffer[:total], nil
		}
		if err != nil {
			return nil, err
		}
		total += n
	}
}

func (d *dlmsal) Open() error { // login and shits
	if d.isopen {
		return nil
	}
	if err := d.transport.Open(); err != nil {
		return err
	}

	b, err := encodeaarq(d.settings)
	if err != nil {
		return err
	}
	err = d.transport.Write(b)
	if err != nil {
		return err
	}
	aare, err := d.smallreadout()
	if err != nil {
		return fmt.Errorf("unable to receive snrm: %v", err)
	}
	// parse aare
	tag, _, data, err := decodetag(aare, d.tmpbuffer)
	if err != nil {
		return fmt.Errorf("unable to parse aare: %v", err)
	}
	if tag != byte(TagAARE) {
		return fmt.Errorf("unexpected tag: %x", tag)
	}
	tags, err := decodeaare(data, d.tmpbuffer)
	if err != nil {
		return fmt.Errorf("unable to parse aare: %v", err)
	}
	for _, dt := range tags {
		switch dt.tag {
		case BERTypeContext | BERTypeConstructed | PduTypeApplicationContextName: // 0xa1
			d.aareres.ApplicationContextName, err = parseApplicationContextName(&dt)
		case BERTypeContext | BERTypeConstructed | PduTypeCalledAPTitle: // 0xa2
			d.aareres.AssociationResult, err = parseAssociationResult(&dt)
		case BERTypeContext | BERTypeConstructed | PduTypeCalledAEQualifier: // 0xa3
			d.aareres.SourceDiagnostic, err = parseAssociateSourceDiagnostic(&dt)
		case BERTypeContext | BERTypeConstructed | PduTypeCalledAPInvocationID: // 0xa4
			d.aareres.SystemTitle, err = parseAPTitle(&dt, d.tmpbuffer)
		case BERTypeContext | BERTypeConstructed | PduTypeUserInformation: // 0xbe
			d.aareres.initiateResponse, d.aareres.confirmedServiceError, err = parseUserInformation(&dt, d.tmpbuffer)
		}

		if err != nil {
			return err
		}
	}

	if d.aareres.ApplicationContextName != d.settings.ApplicationContext {
		return fmt.Errorf("application contextes differ")
	}
	if d.aareres.AssociationResult != AssociationResultAccepted {
		return fmt.Errorf("login failed")
	}
	if d.aareres.SourceDiagnostic != SourceDiagnosticNone {
		return fmt.Errorf("invalid source diagnostic")
	}
	// store aare maybe into context, max pdu info and so on
	if d.aareres.initiateResponse == nil {
		return fmt.Errorf("no initiate response, error probably")
	}
	d.maxPduSendSize = int(d.aareres.initiateResponse.ServerMaxReceivePduSize)
	d.logf("Max PDU size: %v, Va: %v", d.maxPduSendSize, d.aareres.initiateResponse.VAAddress)

	d.settings.VAAddress = d.aareres.initiateResponse.VAAddress // returning from interface, a bit hacky yes

	d.isopen = true
	return nil
}

func (d *dlmsal) SetLogger(logger *zap.SugaredLogger) {
	d.logger = logger
	d.transport.SetLogger(logger)
}
