package ciphering

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"

	"github.com/cybroslabs/hes-2-apis/gen/go/crypto"
	"github.com/cybroslabs/hes-2-apis/gen/go/services/svccrypto"
	"github.com/cybroslabs/libdlms-go/base"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"k8s.io/utils/ptr"
)

type CipheringKMS interface {
	Ciphering
	Dispose()
}

type CipheringKMSSettings struct {
	Logger                    *zap.SugaredLogger
	ServiceClient             svccrypto.CryproServiceClient
	AccessLevel               string
	SerialNumber              string
	DriverId                  string
	ClientTitle               []byte
	CtoS                      []byte
	Context                   context.Context
	AuthenticationMechanismId base.Authentication
}

type cipheringkms struct {
	logger                    *zap.SugaredLogger
	serviceclient             svccrypto.CryproServiceClient
	accessLevel               string
	serialNumber              string
	driverId                  string
	clientTitle               []byte
	ctos                      []byte
	initdone                  bool
	ctx                       context.Context
	stream                    grpc.BidiStreamingClient[crypto.DlmsIn, crypto.DlmsOut]
	cmdid                     uint64
	authenticationMechanismId base.Authentication
}

// Decrypt implements Gcm.
func (g *cipheringkms) Decrypt(ret []byte, sc byte, fc uint32, apdu []byte) ([]byte, error) {
	return g.Decrypt2(ret, sc, sc, fc, apdu)
}

// Encrypt implements Gcm.
func (g *cipheringkms) Encrypt(ret []byte, sc byte, fc uint32, apdu []byte) ([]byte, error) {
	return g.Encrypt2(ret, sc, sc, fc, apdu)
}

func (g *cipheringkms) sendcmd(input *crypto.DlmsIn) ([]byte, error) {
	input.SetId(g.cmdid)
	g.cmdid++
	err := g.stream.Send(input)
	if err != nil {
		return nil, err
	}
	out, err := g.stream.Recv()
	if err != nil {
		return nil, err
	}
	if out.GetId() != input.GetId() {
		return nil, fmt.Errorf("id not match %d != %d", out.GetId(), input.GetId())
	}
	if codes.Code(out.GetError().GetCode()) != codes.OK {
		g.logger.Errorf("error %s", out.GetError().GetMessage())
		return nil, fmt.Errorf("error %s", out.GetError().GetMessage())
	}
	return out.GetData(), nil
}

func (g *cipheringkms) init() (err error) {
	if g.initdone {
		return
	}
	g.stream, err = g.serviceclient.Dlms(g.ctx)
	if err != nil {
		return
	}

	_, err = g.sendcmd(crypto.DlmsIn_builder{
		Init: crypto.DlmsInit_builder{
			Encryption:   ptr.To(crypto.AuthenticatedEncryption_AE_AES_GCM_128),
			Signature:    ptr.To(crypto.DigitalSignature_DS_ECDSA_NONE),
			DriverId:     &g.driverId,
			SerialNumber: &g.serialNumber,
			AccessLevel:  &g.accessLevel,
			SystemTitleC: g.clientTitle,
			CToS:         g.ctos,
		}.Build(),
	}.Build())
	if err != nil {
		_ = g.stream.CloseSend()
		return
	}
	g.initdone = true
	return
}

func (g *cipheringkms) Setup(systemtitleS []byte, stoc []byte) (err error) {
	err = g.init()
	if err != nil {
		return
	}

	_, err = g.sendcmd(crypto.DlmsIn_builder{
		Setup: crypto.DlmsSetServerInfo_builder{
			SystemTitleS: systemtitleS,
			SToC:         stoc,
		}.Build(),
	}.Build())
	return
}

func setcryptomode(a base.Authentication) (cset crypto.Hash, err error) {
	switch a {
	case base.AuthenticationNone:
		err = fmt.Errorf("no authentication mechanism set")
	case base.AuthenticationLow:
		err = fmt.Errorf("low authentication is not supported")
	case base.AuthenticationHigh:
		err = fmt.Errorf("high authentication is not supported")
	case base.AuthenticationHighMD5:
		cset = crypto.Hash_HASH_MD5
	case base.AuthenticationHighSHA1:
		cset = crypto.Hash_HASH_SHA_1
	case base.AuthenticationHighGmac:
		cset = crypto.Hash_HASH_GMAC
	case base.AuthenticationHighSha256:
		cset = crypto.Hash_HASH_SHA_256
	case base.AuthenticationHighEcdsa:
		cset = crypto.Hash_HASH_ECDSA
	default:
		err = fmt.Errorf("invalid authentication mechanism: %v", a)
	}
	return
}

func (g *cipheringkms) Hash(sc byte, fc uint32) ([]byte, error) {
	err := g.init()
	if err != nil {
		return nil, err
	}

	cset, err := setcryptomode(g.authenticationMechanismId)
	if err != nil {
		return nil, err
	}

	return g.sendcmd(crypto.DlmsIn_builder{
		Hash: crypto.DlmsHash_builder{
			Direction:       ptr.To(crypto.HashDirection_CLIENT_TO_SERVER),
			Mode:            ptr.To(cset),
			FrameCounter:    &fc,
			SecurityControl: ptr.To(uint32(sc)),
		}.Build(),
	}.Build())
}

func (g *cipheringkms) Verify(sc byte, fc uint32, hash []byte) (bool, error) {
	err := g.init()
	if err != nil {
		return false, err
	}

	cset, err := setcryptomode(g.authenticationMechanismId)
	if err != nil {
		return false, err
	}

	_, err = g.sendcmd(crypto.DlmsIn_builder{
		AuthVerify: crypto.DlmsAuthVerify_builder{
			Direction:       ptr.To(crypto.HashDirection_SERVER_TO_CLIENT),
			Mode:            ptr.To(cset),
			FrameCounter:    &fc,
			SecurityControl: ptr.To(uint32(sc)),
			Data:            hash,
		}.Build(),
	}.Build())
	if err != nil {
		return false, err
	}
	return true, nil
}

// Decrypt2 implements Gcm.
func (g *cipheringkms) Decrypt2(ret []byte, scControl byte, scContent byte, fc uint32, apdu []byte) ([]byte, error) {
	if scContent != scControl {
		return nil, fmt.Errorf("scContent %02X != scControl %02X", scContent, scControl)
	}

	err := g.init()
	if err != nil {
		return nil, err
	}

	b, err := g.sendcmd(crypto.DlmsIn_builder{
		Decrypt: crypto.DlmsDecrypt_builder{
			FrameCounter:    &fc,
			SecurityControl: ptr.To(uint32(scControl)),
			Data:            apdu,
		}.Build(),
	}.Build())
	if err != nil {
		return nil, err
	}
	// pussyble data copy here
	if ret != nil && cap(ret) >= len(b) {
		ret = ret[:len(b)]
		copy(ret, b)
		return ret, nil
	}
	return b, nil
}

// Encrypt2 implements Gcm.
func (g *cipheringkms) Encrypt2(ret []byte, scControl byte, scContent byte, fc uint32, apdu []byte) ([]byte, error) { // check systitle equality, but it really hurts sending it every packet
	if scContent != scControl {
		return nil, fmt.Errorf("scContent %02X != scControl %02X", scContent, scControl)
	}

	err := g.init()
	if err != nil {
		return nil, err
	}

	b, err := g.sendcmd(crypto.DlmsIn_builder{
		Encrypt: crypto.DlmsEncrypt_builder{
			FrameCounter:    &fc,
			SecurityControl: ptr.To(uint32(scControl)),
			Data:            apdu,
		}.Build(),
	}.Build())
	if err != nil {
		return nil, err
	}
	if ret != nil && cap(ret) >= len(b) {
		ret = ret[:len(b)]
		copy(ret, b)
		return ret, nil
	}
	return b, nil
}

// GetDecryptorStream implements Gcm.
func (g *cipheringkms) GetDecryptorStream(sc byte, fc uint32, apdu io.Reader) (io.Reader, error) {
	return g.GetDecryptorStream2(sc, sc, fc, apdu)
}

// GetDecryptorStream2 implements Gcm.
func (g *cipheringkms) GetDecryptorStream2(scControl byte, scContent byte, fc uint32, apdu io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(apdu) // not streamed at all in this case
	if err != nil {
		return nil, err
	}

	dec, err := g.Decrypt2(nil, scControl, scContent, fc, data)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(dec), nil
}

// GetEncryptLength implements Gcm.
func (g *cipheringkms) GetEncryptLength(scControl byte, apdu []byte) (int, error) {
	switch scControl & 0x30 {
	case 0x10, 0x30:
		return len(apdu) + GCM_TAG_LENGTH, nil
	}
	g.logger.Fatalf("GetEncryptLength not implemented for scControl %02X", scControl)
	panic(fmt.Sprintf("GetEncryptLength not implemented for scControl %02X", scControl)) // shouoldnt reach this point
}

func (g *cipheringkms) Dispose() {
	if g.initdone {
		_ = g.stream.CloseSend()
	}
}

// this is not thread safe at all
func NewCipheringKMS(settings *CipheringKMSSettings) (CipheringKMS, error) { // so only suite 0 right now, just proof of concept
	ret := &cipheringkms{
		logger:                    settings.Logger,
		serviceclient:             settings.ServiceClient,
		accessLevel:               settings.AccessLevel,
		serialNumber:              settings.SerialNumber,
		driverId:                  settings.DriverId,
		initdone:                  false,
		ctx:                       settings.Context,
		authenticationMechanismId: settings.AuthenticationMechanismId,
		clientTitle:               slices.Clone(settings.ClientTitle),
		ctos:                      slices.Clone(settings.CtoS),
	}
	return ret, nil
}
