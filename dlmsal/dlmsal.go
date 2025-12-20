// Package dlmsal implements the DLMS/COSEM application layer protocol.
//
// This package provides a complete implementation of the DLMS (Device Language Message Specification)
// and COSEM (Companion Specification for Energy Metering) application layer, which is used for
// communication with smart meters and other energy management devices.
//
// The package supports:
//   - Logical Name (LN) and Short Name (SN) referencing
//   - Multiple authentication mechanisms (None, Low, High GMAC, SHA-256, ECDSA)
//   - Data encryption using AES-GCM
//   - Block transfer for large data
//   - Profile generic objects for historical data
//   - Selective access for range queries
//
// Basic usage:
//
//	// Create settings
//	settings, _ := dlmsal.NewSettingsWithLowAuthenticationLN("password")
//
//	// Create transport (TCP, HDLC, or Wrapper)
//	transport := tcp.New("192.168.1.100", 4059, 30*time.Second)
//
//	// Create DLMS client
//	client := dlmsal.New(transport, settings)
//
//	// Open connection
//	err := client.Open()
//
//	// Read data
//	items := []dlmsal.DlmsLNRequestItem{{
//		ClassId: 3,
//		Obis: dlmsal.DlmsObis{A: 1, B: 0, C: 1, D: 8, E: 0, F: 255},
//		Attribute: 2,
//	}}
//	data, err := client.Get(items)
package dlmsal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/cybroslabs/libdlms-go/base"
	"github.com/cybroslabs/libdlms-go/ciphering"
	"go.uber.org/zap"
)

const (
	maxsmallreadout  = 2048
	pduoverhead      = 6 + 5 + ciphering.GCM_TAG_LENGTH + 9  // no block header, just length+tag and encoded systitle, 8 bytes + length byte
	pdublockoverhead = 16 + 5 + ciphering.GCM_TAG_LENGTH + 9 // additional block header here
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
	invokeid     byte
	tmpbuffer    tmpbuffer
	pdu          bytes.Buffer // reused for sending requests
	cryptbuffer  []byte       // reusable crypt buffer
	decompbuffer []byte       // reusable decompression buffer
}

// DlmsSettings contains the configuration parameters for DLMS communication.
type DlmsSettings struct {
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
	ServerAuthenticationMechanismId base.Authentication
	UseGeneralGloDedCiphering       bool
	ReturnedConformanceBlock        uint32 // this is returned conformance block, not the one we sent
	ShowSecuredValues               bool   // force to show secured values in logs, dangerous, debug purpose only !!!

	// private part
	ctos              []byte
	invokebyte        byte
	password          []byte
	cipher            ciphering.Ciphering
	clientsystemtitle []byte
	framecounter      uint32
	dedcipher         ciphering.Ciphering
	dedicatedkey      []byte
	computedconf      uint32
}

func (d *DlmsSettings) SetDedicatedKey(key []byte, g ciphering.Ciphering) {
	if key == nil {
		d.dedcipher = nil
	} else {
		d.dedcipher = g
		d.dedicatedkey = slices.Clone(key) // regardless error
	}
}

// NewSettingsWithLowAuthenticationSN creates DLMS settings for Short Name (SN) referencing with low-level authentication.
func NewSettingsWithLowAuthenticationSN(password string) (*DlmsSettings, error) {
	return &DlmsSettings{
		AuthenticationMechanismId: base.AuthenticationLow,
		ApplicationContext:        base.ApplicationContextSNNoCiphering,
		password:                  []byte(password),
		ConformanceBlock: base.ConformanceBlockBlockTransferWithGetOrRead | base.ConformanceBlockBlockTransferWithSetOrWrite |
			base.ConformanceBlockRead | base.ConformanceBlockWrite | base.ConformanceBlockSelectiveAccess | base.ConformanceBlockMultipleReferences,
	}, nil
}

// NewSettingsWithNoAuthenticationSN creates DLMS settings for Short Name (SN) referencing without authentication.
func NewSettingsWithNoAuthenticationSN() (*DlmsSettings, error) {
	return &DlmsSettings{
		AuthenticationMechanismId: base.AuthenticationNone,
		ApplicationContext:        base.ApplicationContextSNNoCiphering,
		ConformanceBlock: base.ConformanceBlockBlockTransferWithGetOrRead | base.ConformanceBlockBlockTransferWithSetOrWrite |
			base.ConformanceBlockRead | base.ConformanceBlockWrite | base.ConformanceBlockSelectiveAccess | base.ConformanceBlockMultipleReferences,
	}, nil
}

// NewSettingsWithLowAuthenticationLN creates DLMS settings for Logical Name (LN) referencing with low-level authentication.
func NewSettingsWithLowAuthenticationLN(password string) (*DlmsSettings, error) {
	return &DlmsSettings{
		AuthenticationMechanismId: base.AuthenticationLow,
		ApplicationContext:        base.ApplicationContextLNNoCiphering,
		password:                  []byte(password),
		HighPriority:              true,
		ConfirmedRequests:         true,
		EmptyRLRQ:                 true,
		ConformanceBlock: base.ConformanceBlockBlockTransferWithGetOrRead | base.ConformanceBlockBlockTransferWithSetOrWrite |
			base.ConformanceBlockBlockTransferWithAction | base.ConformanceBlockAction | base.ConformanceBlockGet | base.ConformanceBlockSet |
			base.ConformanceBlockSelectiveAccess | base.ConformanceBlockMultipleReferences | base.ConformanceBlockAttribute0SupportedWithGet,
	}, nil
}

// NewSettingsWithNoAuthenticationLN creates DLMS settings for Logical Name (LN) referencing without authentication.
func NewSettingsWithNoAuthenticationLN() (*DlmsSettings, error) {
	return &DlmsSettings{
		AuthenticationMechanismId: base.AuthenticationNone,
		ApplicationContext:        base.ApplicationContextLNNoCiphering,
		HighPriority:              true,
		ConfirmedRequests:         true,
		EmptyRLRQ:                 true,
		ConformanceBlock: base.ConformanceBlockBlockTransferWithGetOrRead | base.ConformanceBlockBlockTransferWithSetOrWrite |
			base.ConformanceBlockBlockTransferWithAction | base.ConformanceBlockAction | base.ConformanceBlockGet | base.ConformanceBlockSet |
			base.ConformanceBlockSelectiveAccess | base.ConformanceBlockMultipleReferences | base.ConformanceBlockAttribute0SupportedWithGet,
	}, nil
}

// NewSettingsWithCipheringLN creates DLMS settings for Logical Name (LN) referencing with encryption and authentication.
// The systemtitle must be 8 bytes. The ctoshash is the client-to-server authentication hash.
// fc is the initial frame counter value.
func NewSettingsWithCipheringLN(systemtitle []byte, g ciphering.Ciphering, ctoshash []byte, fc uint32, authmech base.Authentication) (*DlmsSettings, error) {
	if len(systemtitle) != 8 {
		return nil, fmt.Errorf("systemtitle has to be 8 bytes long")
	}
	if len(ctoshash) == 0 {
		return nil, fmt.Errorf("ctoshash is empty")
	}
	ret := DlmsSettings{
		AuthenticationMechanismId: authmech,
		ApplicationContext:        base.ApplicationContextLNCiphering,
		HighPriority:              true,
		ConfirmedRequests:         true,
		EmptyRLRQ:                 true,
		ConformanceBlock: base.ConformanceBlockBlockTransferWithGetOrRead | base.ConformanceBlockBlockTransferWithSetOrWrite |
			base.ConformanceBlockBlockTransferWithAction | base.ConformanceBlockAction | base.ConformanceBlockGet | base.ConformanceBlockSet |
			base.ConformanceBlockSelectiveAccess | base.ConformanceBlockMultipleReferences | base.ConformanceBlockAttribute0SupportedWithGet |
			base.ConformanceBlockGeneralProtection,
		clientsystemtitle: slices.Clone(systemtitle),
		cipher:            g,
		password:          slices.Clone(ctoshash),
		framecounter:      fc,
		Security:          base.SecurityEncryption | base.SecurityAuthentication,
	}
	ret.ctos = ret.password // just reference
	return &ret, nil
}

// New creates a new DLMS application layer client with the specified transport and settings.
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

func (w *dlmsal) dlogf(format string, v ...any) {
	if w.logger != nil {
		w.logger.Debugf(format, v...)
	}
}

func (d *dlmsal) Close() error {
	if !d.transport.isopen {
		// Transport already closed, delegate to lower layers
		return d.transport.Close()
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
	// Read RLRE response (some devices return non-standard responses)
	_, err = d.smallreadout()
	if err != nil {
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
	if d.settings.ShowSecuredValues {
		return false
	}
	switch d.settings.AuthenticationMechanismId {
	case base.AuthenticationLow:
		if st {
			d.transport.SetLogger(d.logger)
		} else {
			d.logf("Temporarily suppressing logs due to packet with confidential content")
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

	// Temporarily suppress logging for all layers when sending confidential data
	if d.logstate(false) {
		d.dlogf(base.LogHex("AARQ (sec values zeroed)", tl))
	}
	err = d.transport.Write(b)
	if err != nil {
		d.logstate(true)
		return err
	}
	aare, err := d.smallreadout()
	if err != nil {
		d.logstate(true)
		return fmt.Errorf("unable to receive AARE: %w", err)
	}
	if d.logstate(true) {
		d.dlogf(base.LogHex("AARE", aare))
	}

	// parse aare
	tag, _, data, err := decodetag(aare, &d.tmpbuffer)
	if err != nil {
		return fmt.Errorf("unable to parse aare: %w", err)
	}
	if tag != byte(base.TagAARE) {
		return fmt.Errorf("unexpected tag: 0x%02x", tag)
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
			d.settings.AssociationResult, err = parseAssociationResult(dt)
		case base.BERTypeContext | base.BERTypeConstructed | base.PduTypeCalledAEQualifier: // 0xa3
			d.settings.SourceDiagnostic, err = parseAssociateSourceDiagnostic(dt)
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
			d.logf("Unknown tag: 0x%02x", dt.tag)
		}

		if err != nil {
			return err
		}
	}

	if d.settings.AssociationResult != base.AssociationResultAccepted {
		return fmt.Errorf("login failed: %s", d.settings.AssociationResult)
	}
	switch d.settings.SourceDiagnostic {
	case base.SourceDiagnosticNone:
	case base.SourceDiagnosticAuthenticationRequired:
	default:
		return fmt.Errorf("invalid source diagnostic: %s", d.settings.SourceDiagnostic)
	}
	if uitag == nil {
		return fmt.Errorf("no user information tag found")
	}
	if d.settings.cipher != nil {
		if mask != 3 {
			return fmt.Errorf("gcm is apparently enabled, but no stoc or serversystemtitle found")
		}
		err = d.settings.cipher.Setup(d.settings.ServerSystemTitle, d.settings.StoC)
		if err != nil {
			return err
		}
	}
	// Setup dedicated cipher if configured (requires StoC and system titles)
	if d.settings.dedcipher != nil {
		if mask != 3 {
			return fmt.Errorf("dedicated gcm is apparently enabled, but no stoc or serversystemtitle found")
		}
		err = d.settings.dedcipher.Setup(d.settings.ServerSystemTitle, d.settings.StoC)
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
	// store aare maybe into context, max pdu info and so on
	if d.aareres.initiateResponse == nil {
		return fmt.Errorf("no initiate response, error probably")
	}
	d.maxPduSendSize = int(d.aareres.initiateResponse.serverMaxReceivePduSize)
	d.logf("Max PDU size: %v, Vaa: %v", d.maxPduSendSize, d.aareres.initiateResponse.vAAddress)

	// Store VAAddress from the server's initiate response
	d.settings.VAAddress = d.aareres.initiateResponse.vAAddress

	d.transport.isopen = true
	return nil
}

func (d *dlmsal) SetLogger(logger *zap.SugaredLogger) {
	d.logger = logger
	d.transport.SetLogger(logger)
}
