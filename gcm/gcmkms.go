package gcm

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/cybroslabs/hes-2-apis/gen/go/crypto"
	"github.com/cybroslabs/hes-2-apis/gen/go/services/svccrypto"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"k8s.io/utils/ptr"
)

type GcmKMS interface {
	Gcm
	Dispose()
}

type GcmKMSSettings struct {
	Logger        *zap.SugaredLogger
	ServiceClient svccrypto.CryproServiceClient
	AccessLevel   string
	SerialNumber  string
	DriverId      string
	ClientTitle   []byte // no ctos yet, suit0 mere encrypt that without additional secret, so not needed
	Context       context.Context
}

type gcmkms struct {
	logger        *zap.SugaredLogger
	serviceclient svccrypto.CryproServiceClient
	accessLevel   string
	serialNumber  string
	driverId      string
	clientTitle   []byte
	initdone      bool
	setupdone     bool
	ctx           context.Context
	stream        grpc.BidiStreamingClient[crypto.DlmsIn, crypto.DlmsOut]
	cmdid         uint64
}

// Decrypt implements Gcm.
func (g *gcmkms) Decrypt(ret []byte, sc byte, fc uint32, systitle []byte, apdu []byte) ([]byte, error) {
	return g.Decrypt2(ret, sc, sc, fc, systitle, apdu)
}

// Encrypt implements Gcm.
func (g *gcmkms) Encrypt(ret []byte, sc byte, fc uint32, systitle []byte, apdu []byte) ([]byte, error) {
	return g.Encrypt2(ret, sc, sc, fc, systitle, apdu)
}

func (g *gcmkms) sendcmd(input *crypto.DlmsIn) ([]byte, error) {
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

func (g *gcmkms) init() (err error) {
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
			CToS:         nil, // TODO: for other crypto types, we need to implement this
		}.Build(),
	}.Build())
	if err != nil {
		_ = g.stream.CloseSend()
		return
	}
	g.initdone = true
	return
}

func (g *gcmkms) setup(systitle []byte) (err error) {
	if g.setupdone {
		return nil
	}
	_, err = g.sendcmd(crypto.DlmsIn_builder{
		Setup: crypto.DlmsSetServerInfo_builder{
			SystemTitleS: systitle,
			SToC:         nil, // TODO: for other crypto types, we need to implement this
		}.Build(),
	}.Build())
	if err != nil {
		g.setupdone = true
	}
	return
}

// Decrypt2 implements Gcm.
func (g *gcmkms) Decrypt2(ret []byte, scControl byte, scContent byte, fc uint32, systitle []byte, apdu []byte) ([]byte, error) {
	if scContent != scControl {
		return nil, fmt.Errorf("scContent %02X != scControl %02X", scContent, scControl)
	}

	err := g.init()
	if err != nil {
		return nil, err
	}
	err = g.setup(systitle)
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
func (g *gcmkms) Encrypt2(ret []byte, scControl byte, scContent byte, fc uint32, _ []byte, apdu []byte) ([]byte, error) { // check systitle equality, but it really hurts sending it every packet
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
func (g *gcmkms) GetDecryptorStream(sc byte, fc uint32, systitle []byte, apdu io.Reader) (io.Reader, error) {
	return g.GetDecryptorStream2(sc, sc, fc, systitle, apdu)
}

// GetDecryptorStream2 implements Gcm.
func (g *gcmkms) GetDecryptorStream2(scControl byte, scContent byte, fc uint32, systitle []byte, apdu io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(apdu) // not streamed at all in this case
	if err != nil {
		return nil, err
	}

	dec, err := g.Decrypt2(nil, scControl, scContent, fc, systitle, data)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(dec), nil
}

// GetEncryptLength implements Gcm.
func (g *gcmkms) GetEncryptLength(scControl byte, apdu []byte) (int, error) {
	switch scControl & 0x30 {
	case 0x10, 0x30:
		return len(apdu) + GCM_TAG_LENGTH, nil
	}
	g.logger.Fatalf("GetEncryptLength not implemented for scControl %02X", scControl)
	panic(fmt.Sprintf("GetEncryptLength not implemented for scControl %02X", scControl)) // shouoldnt reach this point
}

func (g *gcmkms) Dispose() {
	if g.initdone {
		_ = g.stream.CloseSend()
	}
}

// this is not thread safe at all
func NewGCMKMS(settings *GcmKMSSettings) (GcmKMS, error) { // so only suite 0 right now, just proof of concept
	ret := &gcmkms{
		logger:        settings.Logger,
		serviceclient: settings.ServiceClient,
		accessLevel:   settings.AccessLevel,
		serialNumber:  settings.SerialNumber,
		driverId:      settings.DriverId,
		initdone:      false,
		setupdone:     false,
		ctx:           settings.Context,
	}
	ret.clientTitle = append(ret.clientTitle, settings.ClientTitle...) // get copy
	return ret, nil
}
