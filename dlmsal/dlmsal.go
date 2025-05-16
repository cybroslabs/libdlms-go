package dlmsal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"github.com/cybroslabs/libdlms-go/gcm"
	"go.uber.org/zap"
)

const (
	maxsmallreadout  = 2048
	pduoverhead      = 6 + 5 + gcm.GCM_TAG_LENGTH + 9  // no block header, just length+tag and encoded systitle, 8 bytes + length byte
	pdublockoverhead = 16 + 5 + gcm.GCM_TAG_LENGTH + 9 // additional block header here
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
	GetStream(item DlmsLNRequestItem, inmem bool) (DlmsDataStream, error)
	Read(items []DlmsSNRequestItem) ([]DlmsData, error)
	ReadStream(item DlmsSNRequestItem, inmem bool) (DlmsDataStream, error) // only for big single item queries
	Write(items []DlmsSNRequestItem) ([]base.DlmsResultTag, error)
	Action(item DlmsLNRequestItem) (*DlmsData, error)
	Set(items []DlmsLNRequestItem) ([]base.DlmsResultTag, error)
	LNAuthentication(checkresp bool) error
}

type tmpbuffer [128]byte

type dlmsaltransport struct {
	isopen    bool // this is now handled outside
	transport base.Stream
}

func (dt *dlmsaltransport) Read(p []byte) (n int, err error) {
	n, err = dt.transport.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		dt.isopen = false
	}
	return
}

func (dt *dlmsaltransport) Close() error {
	return dt.transport.Close()
}

func (dt *dlmsaltransport) Open() error {
	return dt.transport.Open()
}

func (dt *dlmsaltransport) Disconnect() error {
	return dt.transport.Disconnect()
}

func (dt *dlmsaltransport) SetLogger(logger *zap.SugaredLogger) {
	dt.transport.SetLogger(logger)
}

func (dt *dlmsaltransport) SetDeadline(t time.Time) {
	dt.transport.SetDeadline(t)
}

func (dt *dlmsaltransport) SetTimeout(t time.Duration) {
	dt.transport.SetTimeout(t)
}

func (dt *dlmsaltransport) SetMaxReceivedBytes(m int64) {
	dt.transport.SetMaxReceivedBytes(m)
}

func (dt *dlmsaltransport) Write(src []byte) (err error) {
	err = dt.transport.Write(src)
	if err != nil {
		dt.isopen = false // forcibly close during malfunction
	}
	return
}

func (dt *dlmsaltransport) GetRxTxBytes() (int64, int64) {
	return dt.transport.GetRxTxBytes()
}

type dlmsal struct {
	transport      *dlmsaltransport
	logger         *zap.SugaredLogger
	settings       *DlmsSettings
	aareres        aaResponse
	maxPduSendSize int

	// things for communications/data parsing
	invokeid    byte
	tmpbuffer   tmpbuffer
	pdu         bytes.Buffer // reused for sending requests
	cryptbuffer []byte       // reusable crypt buffer
}

type DlmsSettings struct { // damn too many settings
	ConformanceBlock                uint32
	MaxPduRecvSize                  int
	VAAddress                       int16
	HighPriority                    bool
	ConfirmedRequests               bool
	EmptyRLRQ                       bool
	Security                        base.DlmsSecurity
	StoC                            []byte
	SourceDiagnostic                base.SourceDiagnostic
	AssociationResult               base.AssociationResult
	ServerSystemTitle               []byte
	AuthenticationMechanismId       base.Authentication
	ApplicationContext              base.ApplicationContext
	DontEncryptUserInformation      bool
	UserId                          *byte
	ServerUserId                    byte
	ClientCertificate               *x509.Certificate
	ClientPrivateKey                *ecdsa.PrivateKey
	ServerCertificate               *x509.Certificate // could be returned during AARE
	ServerAuthenticationMechanismId base.Authentication
	PerformSigning                  bool
	UseGeneralGloDedCiphering       bool

	// private part
	ctos              []byte
	invokebyte        byte
	password          []byte
	gcm               gcm.Gcm
	clientsystemtitle []byte
	framecounter      uint32
	dedgcm            gcm.Gcm
	dedicatedkey      []byte
}

func (d *DlmsSettings) SetDedicatedKey(key []byte, g gcm.Gcm) {
	if key == nil {
		d.dedgcm = nil
	} else {
		d.dedgcm = g
		d.dedicatedkey = newcopy(key) // regardless error
	}
}

func NewSettingsWithLowAuthenticationSN(password string) (*DlmsSettings, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password is empty")
	}
	return &DlmsSettings{
		AuthenticationMechanismId: base.AuthenticationLow,
		ApplicationContext:        base.ApplicationContextSNNoCiphering,
		password:                  []byte(password),
		ConformanceBlock: base.ConformanceBlockBlockTransferWithGetOrRead | base.ConformanceBlockBlockTransferWithSetOrWrite |
			base.ConformanceBlockRead | base.ConformanceBlockWrite | base.ConformanceBlockSelectiveAccess | base.ConformanceBlockMultipleReferences,
	}, nil
}

func NewSettingsWithLowAuthenticationLN(password string) (*DlmsSettings, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password is empty")
	}
	return &DlmsSettings{
		AuthenticationMechanismId: base.AuthenticationLow,
		ApplicationContext:        base.ApplicationContextLNNoCiphering,
		password:                  []byte(password),
		HighPriority:              true,
		ConfirmedRequests:         true,
		ConformanceBlock: base.ConformanceBlockBlockTransferWithGetOrRead | base.ConformanceBlockBlockTransferWithSetOrWrite |
			base.ConformanceBlockBlockTransferWithAction | base.ConformanceBlockAction | base.ConformanceBlockGet | base.ConformanceBlockSet |
			base.ConformanceBlockSelectiveAccess | base.ConformanceBlockMultipleReferences | base.ConformanceBlockAttribute0SupportedWithGet,
	}, nil
}

func NewSettingsNoAuthenticationLN() (*DlmsSettings, error) {
	return &DlmsSettings{
		AuthenticationMechanismId: base.AuthenticationNone,
		ApplicationContext:        base.ApplicationContextLNNoCiphering,
		HighPriority:              true,
		ConfirmedRequests:         true,
		ConformanceBlock: base.ConformanceBlockBlockTransferWithGetOrRead | base.ConformanceBlockBlockTransferWithSetOrWrite |
			base.ConformanceBlockBlockTransferWithAction | base.ConformanceBlockAction | base.ConformanceBlockGet | base.ConformanceBlockSet |
			base.ConformanceBlockSelectiveAccess | base.ConformanceBlockMultipleReferences | base.ConformanceBlockAttribute0SupportedWithGet,
	}, nil
}

func NewSettingsWithGmacLN(systemtitle []byte, g gcm.Gcm, ctoshash []byte, fc uint32) (*DlmsSettings, error) {
	if len(systemtitle) != 8 {
		return nil, fmt.Errorf("systemtitle has to be 8 bytes long")
	}
	if len(ctoshash) == 0 {
		return nil, fmt.Errorf("ctoshash is empty")
	}
	ret := DlmsSettings{
		AuthenticationMechanismId: base.AuthenticationHighGmac,
		ApplicationContext:        base.ApplicationContextLNCiphering,
		HighPriority:              true,
		ConfirmedRequests:         true,
		ConformanceBlock: base.ConformanceBlockBlockTransferWithGetOrRead | base.ConformanceBlockBlockTransferWithSetOrWrite |
			base.ConformanceBlockBlockTransferWithAction | base.ConformanceBlockAction | base.ConformanceBlockGet | base.ConformanceBlockSet |
			base.ConformanceBlockSelectiveAccess | base.ConformanceBlockMultipleReferences | base.ConformanceBlockAttribute0SupportedWithGet |
			base.ConformanceBlockGeneralProtection,
		clientsystemtitle: newcopy(systemtitle),
		gcm:               g,
		password:          newcopy(ctoshash),
		framecounter:      fc,
		Security:          base.SecurityEncryption | base.SecurityAuthentication,
	}
	ret.ctos = ret.password // just reference
	return &ret, nil
}

func NewSettingsWithEcdsaLN(systemtitle []byte, g gcm.Gcm, ctoshash []byte, fc uint32, serverCertificate *x509.Certificate) (*DlmsSettings, error) {
	if len(systemtitle) != 8 {
		return nil, fmt.Errorf("systemtitle has to be 8 bytes long")
	}
	if len(ctoshash) < 32 {
		return nil, fmt.Errorf("ctoshash is too short, it has to be at least 32 bytes long")
	}
	if serverCertificate == nil {
		return nil, fmt.Errorf("server certificate is nil")
	}
	if _, ok := serverCertificate.PublicKey.(*ecdsa.PublicKey); !ok {
		return nil, fmt.Errorf("server certificate doesnt have ecdsa public key")
	}

	ret := DlmsSettings{
		AuthenticationMechanismId: base.AuthenticationHighEcdsa,
		ApplicationContext:        base.ApplicationContextLNCiphering,
		HighPriority:              true,
		ConfirmedRequests:         true,
		ConformanceBlock: base.ConformanceBlockBlockTransferWithGetOrRead | base.ConformanceBlockBlockTransferWithSetOrWrite |
			base.ConformanceBlockBlockTransferWithAction | base.ConformanceBlockAction | base.ConformanceBlockGet | base.ConformanceBlockSet |
			base.ConformanceBlockSelectiveAccess | base.ConformanceBlockMultipleReferences | base.ConformanceBlockAttribute0SupportedWithGet |
			base.ConformanceBlockGeneralProtection,
		clientsystemtitle: newcopy(systemtitle),
		gcm:               g,
		password:          newcopy(ctoshash),
		framecounter:      fc,
		Security:          base.SecurityEncryption | base.SecurityAuthentication | base.SecuritySuite2,
		ServerCertificate: serverCertificate,
	}

	ret.ctos = ret.password // just reference
	return &ret, nil
}

func New(transport base.Stream, settings *DlmsSettings) DlmsClient {
	settings.invokebyte = 0
	if settings.HighPriority {
		settings.invokebyte |= 0x80
	}
	if settings.ConfirmedRequests {
		settings.invokebyte |= 0x40
	}
	return &dlmsal{
		transport: &dlmsaltransport{
			isopen:    false,
			transport: transport,
		},
		logger:   nil,
		settings: settings,
		invokeid: 0,
	}
}

func (w *dlmsal) logf(format string, v ...any) {
	if w.logger != nil {
		w.logger.Infof(format, v...)
	}
}

func (d *dlmsal) Close() error {
	if !d.transport.isopen {
		return d.transport.Close() // a bit questionable
	}
	d.transport.isopen = false // close that preemtpively, not ideal...

	rl, err := encodeRLRQ(d.settings)
	if err != nil {
		_ = d.transport.Close() // close lower layers at all cost
		return err
	}
	err = d.transport.Write(rl)
	if err != nil {
		_ = d.transport.Close() // close lower layers at all cost
		return err
	}
	_, err = d.smallreadout() // yes, this is bullshit
	if err != nil {           // just ignore data itself as simulator returns some weird shit (based on e650 maybe)
		_ = d.transport.Close() // close lower layers at all cost
		return err
	}

	return d.transport.Close()
}

func (d *dlmsal) Disconnect() error {
	d.transport.isopen = false
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
		if err != nil {
			if errors.Is(err, io.EOF) {
				return ret[:total], nil
			}
			return nil, err
		}
	}
}

func (d *dlmsal) logstate(st bool) bool {
	switch d.settings.AuthenticationMechanismId {
	case base.AuthenticationLow:
		if st {
			d.transport.SetLogger(d.logger)
		} else {
			d.logf("temporary stop logging due to packet with confidental content")
			d.transport.SetLogger(nil)
		}
		return true
	}
	return false
}

func (d *dlmsal) Open() error { // login and shits
	if d.transport.isopen {
		return nil
	}
	if err := d.transport.Open(); err != nil {
		return err
	}
	b, tl, err := d.encodeaarq()
	if err != nil {
		return err
	}

	if d.logstate(false) { // potencially not logging from all layer, not just that password, but nothing...
		d.logf(base.LogHex("AARQ (sec values zeroed)", tl))
	}
	err = d.transport.Write(b)
	if err != nil {
		d.logstate(true)
		return err
	}
	aare, err := d.smallreadout()
	if err != nil {
		d.logstate(true)
		return fmt.Errorf("unable to receive snrm: %w", err)
	}
	if d.logstate(true) {
		d.logf(base.LogHex("AARE", aare))
	}

	// parse aare
	tag, _, data, err := decodetag(aare, &d.tmpbuffer)
	if err != nil {
		return fmt.Errorf("unable to parse aare: %w", err)
	}
	if tag != byte(base.TagAARE) {
		return fmt.Errorf("unexpected tag: %x", tag)
	}
	tags, err := decodeaare(data, &d.tmpbuffer)
	if err != nil {
		return fmt.Errorf("unable to parse aare: %w", err)
	}
	var uitag *aaretag
	mask := 0
	for _, dt := range tags {
		switch dt.tag {
		case base.BERTypeContext | base.BERTypeConstructed | base.PduTypeApplicationContextName: // 0xa1
			d.aareres.applicationContextName, err = parseApplicationContextName(dt)
		case base.BERTypeContext | base.BERTypeConstructed | base.PduTypeCalledAPTitle: // 0xa2
			d.aareres.associationResult, err = parseAssociationResult(dt)
		case base.BERTypeContext | base.BERTypeConstructed | base.PduTypeCalledAEQualifier: // 0xa3
			d.aareres.sourceDiagnostic, err = parseAssociateSourceDiagnostic(dt)
		case base.BERTypeContext | base.BERTypeConstructed | base.PduTypeCalledAPInvocationID: // 0xa4
			d.settings.ServerSystemTitle, err = parseAPTitle(dt, &d.tmpbuffer)
			mask |= 1
		case base.BERTypeContext | base.BERTypeConstructed | base.PduTypeCalledAEInvocationID: // 0xa5
			err = d.parseCalledAEInvocationID(dt)
		case base.BERTypeContext | base.BERTypeConstructed | base.PduTypeSenderAcseRequirements: // 0xaa
			d.settings.StoC, err = parseSenderAcseRequirements(dt, &d.tmpbuffer)
			mask |= 2
		case base.BERTypeContext | base.BERTypeConstructed | base.PduTypeUserInformation: // 0xbe
			uitag = &dt
		case base.BERTypeContext | base.PduTypeCallingAPInvocationID: // 0x88
			err = parseAcsefield(dt)
		case base.BERTypeContext | base.PduTypeCallingAEInvocationID: // 0x89
			d.settings.ServerAuthenticationMechanismId, err = parseAEInvocationID(dt)
		default:
			d.logf("Unknown tag: %02x", dt.tag)
		}

		if err != nil {
			return err
		}
	}

	if uitag == nil {
		return fmt.Errorf("no user information tag found")
	}
	if d.settings.gcm != nil {
		if mask != 3 {
			return fmt.Errorf("gcm is apparently enabled, but no stoc or serversystemtitle found")
		}
		err = d.settings.gcm.Setup(d.settings.ServerSystemTitle, d.settings.StoC)
		if err != nil {
			return err
		}
	}
	if d.settings.dedgcm != nil { // a bit questionable, if there is already gcm, there should be also stoc and systemtitles
		if mask != 3 {
			return fmt.Errorf("dedicated gcm is apparently enabled, but no stoc or serversystemtitle found")
		}
		err = d.settings.dedgcm.Setup(d.settings.ServerSystemTitle, d.settings.StoC)
		if err != nil {
			return err
		}
	}
	d.aareres.initiateResponse, d.aareres.confirmedServiceError, err = d.parseUserInformation(*uitag)
	if err != nil {
		return fmt.Errorf("unable to parse user information: %w", err)
	}

	if d.aareres.confirmedServiceError != nil {
		return fmt.Errorf("confirmed service error: %v", d.aareres.confirmedServiceError.ConfirmedServiceError)
	}
	if d.aareres.applicationContextName != d.settings.ApplicationContext {
		return fmt.Errorf("application contextes differ: %v != %v", d.aareres.applicationContextName, d.settings.ApplicationContext)
	}
	if d.aareres.associationResult != base.AssociationResultAccepted {
		return fmt.Errorf("login failed: %v", d.aareres.associationResult)
	}
	d.settings.SourceDiagnostic = d.aareres.sourceDiagnostic // duplicit information, damn it, maybe make a bit bigger settings, or maybe status?
	d.settings.AssociationResult = d.aareres.associationResult
	switch d.aareres.sourceDiagnostic {
	case base.SourceDiagnosticNone:
	case base.SourceDiagnosticAuthenticationRequired:
	default:
		return fmt.Errorf("invalid source diagnostic: %v", d.aareres.sourceDiagnostic)
	}
	// store aare maybe into context, max pdu info and so on
	if d.aareres.initiateResponse == nil {
		return fmt.Errorf("no initiate response, error probably")
	}
	d.maxPduSendSize = int(d.aareres.initiateResponse.ServerMaxReceivePduSize)
	d.logf("Max PDU size: %v, Vaa: %v", d.maxPduSendSize, d.aareres.initiateResponse.VAAddress)

	d.settings.VAAddress = d.aareres.initiateResponse.VAAddress // returning from interface, a bit hacky yes

	d.transport.isopen = true
	return nil
}

func (d *dlmsal) SetLogger(logger *zap.SugaredLogger) {
	d.logger = logger
	d.transport.SetLogger(logger)
}
