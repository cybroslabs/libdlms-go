package dlmsal

import (
	"bytes"
	"fmt"
	"io"

	"github.com/cybroslabs/libdlms-go/base"
	"github.com/cybroslabs/libdlms-go/gcm"
	"go.uber.org/zap"
)

const (
	DlmsVersion = 0x06

	VAANameLN = 0x0007
	VAANameSN = 0xFA00

	maxsmallreadout = 2048
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

type DlmsSecurity byte

const (
	SecurityNone           DlmsSecurity = 0    // Transport security is not used.
	SecurityAuthentication DlmsSecurity = 0x10 // Authentication security is used.
	SecurityEncryption     DlmsSecurity = 0x20 // Encryption security is used.
)

type DlmsSNRequestItem struct {
	Address          int16
	HasAccess        bool
	AccessDescriptor byte
	AccessData       *DlmsData
	WriteData        *DlmsData
}

type DlmsLNRequestItem struct {
	ClassId uint16
	Obis    DlmsObis
	// also method id
	Attribute        int8
	HasAccess        bool
	AccessDescriptor byte
	AccessData       *DlmsData
	// also action data
	SetData *DlmsData
}

type DlmsClient interface {
	Close() error
	Disconnect() error
	Open() error
	SetLogger(logger *zap.SugaredLogger)
	Get(items []DlmsLNRequestItem) ([]DlmsData, error)
	GetStream(item DlmsLNRequestItem, inmem bool) (DlmsDataStream, *DlmsError, error)
	Read(items []DlmsSNRequestItem) ([]DlmsData, error)
	ReadStream(item DlmsSNRequestItem, inmem bool) (DlmsDataStream, *DlmsError, error) // only for big single item queries
	Write(items []DlmsSNRequestItem) ([]AccessResultTag, error)
	Action(item DlmsLNRequestItem) (*DlmsData, error)
	Set(items []DlmsLNRequestItem) ([]AccessResultTag, error)
	LNAuthentication(checkresp bool) error
}

type tmpbuffer [128]byte

type dlmsal struct {
	transport      base.Stream
	logger         *zap.SugaredLogger
	settings       *DlmsSettings
	isopen         bool
	aareres        AAResponse
	maxPduSendSize int

	// things for communications/data parsing
	invokeid    byte
	tmpbuffer   tmpbuffer
	pdu         bytes.Buffer // reused for sending requests
	cryptbuffer []byte       // reusable crypt buffer
}

type DlmsSettings struct {
	ConformanceBlock  uint32
	MaxPduRecvSize    int
	VAAddress         int16
	HighPriority      byte
	ConfirmedRequests byte
	EmptyRLRQ         bool
	Security          DlmsSecurity
	StoC              []byte
	CtoS              []byte
	SourceDiagnostic  SourceDiagnostic

	// private part
	authentication     Authentication
	applicationContext ApplicationContext
	password           []byte
	gcm                gcm.Gcm
	systemtitle        []byte
	framecounter       uint32
	usededicatedkey    bool
	dedgcm             gcm.Gcm
	dedicatedkey       []byte
	akcopy             []byte
}

func (d *DlmsSettings) SetDedicatedKey(key []byte) (err error) {
	if key == nil {
		d.dedgcm = nil
	} else {
		d.dedgcm, err = gcm.NewGCM(key, d.akcopy)
		d.dedicatedkey = newcopy(key) // regardless error
	}
	return
}

func NewSettingsWithLowAuthenticationSN(password string) (*DlmsSettings, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password is empty")
	}
	return &DlmsSettings{
		authentication:     AuthenticationLow,
		applicationContext: ApplicationContextSNNoCiphering,
		password:           []byte(password),
		ConformanceBlock: ConformanceBlockBlockTransferWithGetOrRead | ConformanceBlockBlockTransferWithSetOrWrite |
			ConformanceBlockRead | ConformanceBlockWrite | ConformanceBlockSelectiveAccess | ConformanceBlockMultipleReferences,
	}, nil
}

func NewSettingsWithLowAuthenticationLN(password string) (*DlmsSettings, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password is empty")
	}
	return &DlmsSettings{
		authentication:     AuthenticationLow,
		applicationContext: ApplicationContextLNNoCiphering,
		password:           []byte(password),
		HighPriority:       0x80,
		ConfirmedRequests:  0x40,
		ConformanceBlock: ConformanceBlockBlockTransferWithGetOrRead | ConformanceBlockBlockTransferWithSetOrWrite |
			ConformanceBlockBlockTransferWithAction | ConformanceBlockAction | ConformanceBlockGet | ConformanceBlockSet |
			ConformanceBlockSelectiveAccess | ConformanceBlockMultipleReferences | ConformanceBlockAttribute0SupportedWithGet,
	}, nil
}

func NewSettingsNoAuthenticationLN() (*DlmsSettings, error) {
	return &DlmsSettings{
		authentication:     AuthenticationNone,
		applicationContext: ApplicationContextLNNoCiphering,
		HighPriority:       0x80,
		ConfirmedRequests:  0x40,
		ConformanceBlock: ConformanceBlockBlockTransferWithGetOrRead | ConformanceBlockBlockTransferWithSetOrWrite |
			ConformanceBlockBlockTransferWithAction | ConformanceBlockAction | ConformanceBlockGet | ConformanceBlockSet |
			ConformanceBlockSelectiveAccess | ConformanceBlockMultipleReferences | ConformanceBlockAttribute0SupportedWithGet,
	}, nil
}

func NewSettingsWithGmacLN(systemtitle []byte, ek []byte, ak []byte, ctoshash []byte, fc uint32) (*DlmsSettings, error) {
	if len(systemtitle) != 8 {
		return nil, fmt.Errorf("systemtitle has to be 8 bytes long")
	}
	if len(ctoshash) == 0 {
		return nil, fmt.Errorf("ctoshash is empty")
	}
	g, err := gcm.NewGCM(ek, ak)
	if err != nil {
		return nil, err
	}
	ret := DlmsSettings{
		authentication:     AuthenticationHighGmac,
		applicationContext: ApplicationContextLNCiphering,
		HighPriority:       0x80,
		ConfirmedRequests:  0x40,
		ConformanceBlock: ConformanceBlockBlockTransferWithGetOrRead | ConformanceBlockBlockTransferWithSetOrWrite |
			ConformanceBlockBlockTransferWithAction | ConformanceBlockAction | ConformanceBlockGet | ConformanceBlockSet |
			ConformanceBlockSelectiveAccess | ConformanceBlockMultipleReferences | ConformanceBlockAttribute0SupportedWithGet |
			ConformanceBlockGeneralProtection,
		systemtitle:  newcopy(systemtitle),
		gcm:          g,
		akcopy:       newcopy(ak), // this is sad...
		password:     newcopy(ctoshash),
		framecounter: fc,
		Security:     SecurityEncryption | SecurityAuthentication,
	}
	ret.CtoS = ret.password // just reference
	return &ret, nil
}

func New(transport base.Stream, settings *DlmsSettings) DlmsClient {
	return &dlmsal{
		transport: transport,
		logger:    nil,
		settings:  settings,
		isopen:    false,
		invokeid:  0,
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
	_, err = d.smallreadout() // yes, this is bullshit
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

func (d *dlmsal) smallreadout() ([]byte, error) {
	// safely use already existing buffer, it could fail if aare is bigger than it, but it can be solved later
	total := 0
	ret := make([]byte, 128)
	for {
		if total == len(ret) {
			if total >= maxsmallreadout {
				return nil, fmt.Errorf("no room for aare or rlre (or smallreadout)")
			}
			dt := make([]byte, len(ret)+128)
			copy(dt, ret)
			ret = dt
		}

		n, err := d.transport.Read(ret[total:])
		total += n
		if err == io.EOF {
			return ret[:total], nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func (d *dlmsal) Open() error { // login and shits
	if d.isopen {
		return nil
	}
	if err := d.transport.Open(); err != nil {
		return err
	}

	b, err := d.encodeaarq()
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
	tag, _, data, err := decodetag(aare, &d.tmpbuffer)
	if err != nil {
		return fmt.Errorf("unable to parse aare: %v", err)
	}
	if tag != byte(TagAARE) {
		return fmt.Errorf("unexpected tag: %x", tag)
	}
	tags, err := decodeaare(data, &d.tmpbuffer)
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
			d.aareres.SystemTitle, err = parseAPTitle(&dt, &d.tmpbuffer)
		case BERTypeContext | BERTypeConstructed | PduTypeSenderAcseRequirements: // 0xaa
			d.settings.StoC, err = parseSenderAcseRequirements(&dt, &d.tmpbuffer)
		case BERTypeContext | BERTypeConstructed | PduTypeUserInformation: // 0xbe
			d.aareres.initiateResponse, d.aareres.confirmedServiceError, err = d.parseUserInformation(&dt)
		default:
			d.logf("Unknown tag: %02x", dt.tag)
		}

		if err != nil {
			return err
		}
	}

	if d.aareres.confirmedServiceError != nil {
		return fmt.Errorf("confirmed service error: %v", d.aareres.confirmedServiceError.ConfirmedServiceError)
	}
	if d.aareres.ApplicationContextName != d.settings.applicationContext {
		return fmt.Errorf("application contextes differ: %v != %v", d.aareres.ApplicationContextName, d.settings.applicationContext)
	}
	if d.aareres.AssociationResult != AssociationResultAccepted {
		return fmt.Errorf("login failed: %v", d.aareres.AssociationResult)
	}
	d.settings.SourceDiagnostic = d.aareres.SourceDiagnostic // duplicit information, damn it, maybe make a bit bigger settings, or maybe status?
	switch d.aareres.SourceDiagnostic {
	case SourceDiagnosticNone:
	case SourceDiagnosticAuthenticationRequired:
	default:
		return fmt.Errorf("invalid source diagnostic: %v", d.aareres.SourceDiagnostic)
	}
	// store aare maybe into context, max pdu info and so on
	if d.aareres.initiateResponse == nil {
		return fmt.Errorf("no initiate response, error probably")
	}
	d.maxPduSendSize = int(d.aareres.initiateResponse.ServerMaxReceivePduSize)
	d.logf("Max PDU size: %v, Vaa: %v", d.maxPduSendSize, d.aareres.initiateResponse.VAAddress)

	d.settings.VAAddress = d.aareres.initiateResponse.VAAddress // returning from interface, a bit hacky yes

	d.isopen = true
	return nil
}

func (d *dlmsal) SetLogger(logger *zap.SugaredLogger) {
	d.logger = logger
	d.transport.SetLogger(logger)
}
