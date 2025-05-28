package ciphering

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"slices"

	"github.com/cybroslabs/libdlms-go/base"
)

type cipheringnist struct {
	nist cipher.AEAD
	aad  []byte
	iv   [12]byte

	password     []byte
	systemtitleC []byte
	systemtitleS []byte
	stoc         []byte
	ctos         []byte

	authenticationMechanismId base.Authentication
	clientPrivateKey          *ecdsa.PrivateKey
	serverCertificate         *x509.Certificate
}

// Decrypt implements Gcm.
func (g *cipheringnist) Decrypt(ret []byte, sc byte, fc uint32, apdu []byte) ([]byte, error) {
	return g.Decrypt2(ret, sc, sc, fc, apdu)
}

// Encrypt implements Gcm.
func (g *cipheringnist) Encrypt(ret []byte, sc byte, fc uint32, apdu []byte) ([]byte, error) {
	return g.encryptinternal(ret, sc, sc, fc, g.systemtitleC, apdu)
}

func (g *cipheringnist) Setup(systemtitleS []byte, stoc []byte) (err error) {
	if len(systemtitleS) != 8 {
		return fmt.Errorf("systitle has to be 8 bytes long")
	}
	g.systemtitleS = slices.Clone(systemtitleS)
	g.stoc = slices.Clone(stoc)
	return nil
}

func (g *cipheringnist) Hash(sc byte, fc uint32) ([]byte, error) {
	var hashbuf bytes.Buffer
	switch g.authenticationMechanismId {
	case base.AuthenticationLow:
		return slices.Clone(g.password), nil
	case base.AuthenticationHighMD5:
		hashbuf.Write(g.systemtitleS)
		hashbuf.Write(g.password)
		h := md5.Sum(hashbuf.Bytes())
		return h[:], nil
	case base.AuthenticationHighSHA1:
		hashbuf.Write(g.systemtitleS)
		hashbuf.Write(g.password)
		h := sha1.Sum(hashbuf.Bytes())
		return h[:], nil
	case base.AuthenticationHighGmac:
		e, err := g.encryptinternal(nil, sc, sc, fc, g.systemtitleC, g.stoc)
		if err != nil {
			return nil, err
		}
		if len(e) < GCM_TAG_LENGTH { // definitely shouldnt happen
			return nil, fmt.Errorf("encrypted data too short")
		}
		return e[len(e)-GCM_TAG_LENGTH:], nil
	case base.AuthenticationHighSha256:
		hashbuf.Write(g.password)
		hashbuf.Write(g.systemtitleC)
		hashbuf.Write(g.systemtitleS)
		hashbuf.Write(g.stoc)
		hashbuf.Write(g.ctos)
		h := sha256.Sum256(hashbuf.Bytes())
		return h[:], nil
	case base.AuthenticationHighEcdsa:
		if g.clientPrivateKey == nil {
			return nil, fmt.Errorf("ecdsa private key not set, this is required for ecdsa authentication")
		}
		hashbuf.Write(g.systemtitleC)
		hashbuf.Write(g.systemtitleS)
		hashbuf.Write(g.stoc)
		hashbuf.Write(g.ctos)
		var hashdata []byte
		switch g.clientPrivateKey.Curve.Params().BitSize {
		case 256:
			h := sha256.Sum256(hashbuf.Bytes())
			hashdata = h[:]
		case 384:
			h := sha512.Sum384(hashbuf.Bytes())
			hashdata = h[:]
		default:
			return nil, fmt.Errorf("unsupported curve %v", g.clientPrivateKey.Curve.Params().BitSize)
		}

		bigr, bifs, err := ecdsa.Sign(rand.Reader, g.clientPrivateKey, hashdata)
		if err != nil {
			return nil, fmt.Errorf("unable to sign with ecdsa: %w", err)
		}

		hashbuf.Reset()
		hashbuf.Write(bigr.Bytes())
		hashbuf.Write(bifs.Bytes())
		return hashbuf.Bytes(), nil
	}

	return nil, fmt.Errorf("unsupported authentication mechanism: %v", g.authenticationMechanismId)
}

func (g *cipheringnist) Verify(sc byte, fc uint32, hash []byte) (bool, error) {
	var hashbuf bytes.Buffer
	switch g.authenticationMechanismId {
	case base.AuthenticationLow:
		return bytes.Equal(hash, g.password), nil
	case base.AuthenticationHighMD5:
		hashbuf.Write(g.ctos)
		hashbuf.Write(g.password)
		h := md5.Sum(hashbuf.Bytes())
		return bytes.Equal(hash, h[:]), nil
	case base.AuthenticationHighSHA1:
		hashbuf.Write(g.ctos)
		hashbuf.Write(g.password)
		h := sha1.Sum(hashbuf.Bytes())
		return bytes.Equal(hash, h[:]), nil
	case base.AuthenticationHighGmac:
		e, err := g.encryptinternal(nil, sc, sc, fc, g.systemtitleS, g.ctos)
		if err != nil {
			return false, err
		}
		if len(e) < GCM_TAG_LENGTH { // definitely shouldnt happen
			return false, fmt.Errorf("encrypted data too short")
		}
		return bytes.Equal(e[len(e)-GCM_TAG_LENGTH:], hash), nil
	case base.AuthenticationHighSha256:
		hashbuf.Write(g.password)
		hashbuf.Write(g.systemtitleS)
		hashbuf.Write(g.systemtitleC)
		hashbuf.Write(g.ctos)
		hashbuf.Write(g.stoc)
		h := sha256.Sum256(hashbuf.Bytes())
		return bytes.Equal(hash, h[:]), nil
	case base.AuthenticationHighEcdsa:
		if g.serverCertificate == nil {
			return false, fmt.Errorf("ecdsa server certificate not set, this is required for ecdsa authentication")
		}
		if len(hash) == 0 || len(hash)&1 != 0 {
			return false, fmt.Errorf("invalid ecdsa authmech response length")
		}

		switch pubkey := g.serverCertificate.PublicKey.(type) {
		case *ecdsa.PublicKey:
			hashbuf.Write(g.systemtitleS)
			hashbuf.Write(g.systemtitleC)
			hashbuf.Write(g.ctos)
			hashbuf.Write(g.stoc)

			var hashdata []byte
			switch pubkey.Curve.Params().BitSize {
			case 256:
				h := sha256.Sum256(hashbuf.Bytes())
				hashdata = h[:]
			case 384:
				h := sha512.Sum384(hashbuf.Bytes())
				hashdata = h[:]
			default:
				return false, fmt.Errorf("unsupported curve %v", pubkey.Curve.Params().BitSize)
			}

			var big_r, big_s big.Int
			big_r.SetBytes(hash[:len(hash)/2])
			big_s.SetBytes(hash[len(hash)/2:])
			return ecdsa.Verify(pubkey, hashdata, &big_r, &big_s), nil
		default:
			return false, fmt.Errorf("invalid ecdsa server certificate")
		}
	}

	return false, fmt.Errorf("unsupported authentication mechanism: %v", g.authenticationMechanismId)
}

// Decrypt2 implements Gcm.
func (g *cipheringnist) Decrypt2(ret []byte, scControl byte, scContent byte, fc uint32, apdu []byte) ([]byte, error) {
	if apdu == nil {
		return nil, fmt.Errorf("apdu is nil")
	}
	switch g.authenticationMechanismId {
	case base.AuthenticationHighGmac, base.AuthenticationHighSha256, base.AuthenticationHighEcdsa:
	default:
		if ret != nil && cap(ret) >= len(apdu) {
			ret = ret[:len(apdu)]
		} else {
			ret = make([]byte, len(apdu))
		}
		copy(ret, apdu) // in that case, yes, wasteful copy, but it should be copied as we dont know if apdu wont be reused
		return ret, nil
	}

	copy(g.iv[:], g.systemtitleS)
	binary.BigEndian.PutUint32(g.iv[8:], fc)
	switch scControl & 0x30 {
	case 0x10:
		if len(apdu) < GCM_TAG_LENGTH {
			return nil, fmt.Errorf("too short ciphered data, no space for tag")
		}
		aad := make([]byte, len(g.aad)+len(apdu)-GCM_TAG_LENGTH)
		aad[0] = scContent
		copy(aad[1:], g.aad[1:])
		copy(aad[len(g.aad):], apdu[:len(apdu)-GCM_TAG_LENGTH])
		_, err := g.nist.Open(nil, g.iv[:], apdu[:len(apdu)-GCM_TAG_LENGTH], aad)
		if err != nil {
			return nil, err
		}
		if cap(ret) >= len(apdu)-GCM_TAG_LENGTH {
			return append(ret[:0], apdu[:len(apdu)-GCM_TAG_LENGTH]...), nil
		}
		return slices.Clone(apdu[:len(apdu)-GCM_TAG_LENGTH]), nil // make a copy?
	case 0x30:
		if len(apdu) < GCM_TAG_LENGTH {
			return nil, fmt.Errorf("too short ciphered data, no space for tag")
		}
		g.aad[0] = scContent
		return g.nist.Open(ret[:0], g.iv[:], apdu, g.aad)
	default:
		return nil, fmt.Errorf("scControl %02X not supported", scControl)
	}
}

// Encrypt2 implements Gcm.
func (g *cipheringnist) Encrypt2(ret []byte, scControl byte, scContent byte, fc uint32, apdu []byte) ([]byte, error) { // check systitle equality, but it really hurts sending it every packet
	return g.encryptinternal(ret, scControl, scContent, fc, g.systemtitleC, apdu)
}

func (g *cipheringnist) encryptinternal(ret []byte, scControl byte, scContent byte, fc uint32, title []byte, apdu []byte) ([]byte, error) { // check systitle equality, but it really hurts sending it every packet
	if apdu == nil {
		return nil, fmt.Errorf("apdu is nil")
	}
	switch g.authenticationMechanismId {
	case base.AuthenticationHighGmac, base.AuthenticationHighSha256, base.AuthenticationHighEcdsa:
	default:
		if ret != nil && cap(ret) >= len(apdu) {
			ret = ret[:len(apdu)]
		} else {
			ret = make([]byte, len(apdu))
		}
		copy(ret, apdu)
		return ret, nil
	}

	copy(g.iv[:], title)
	binary.BigEndian.PutUint32(g.iv[8:], fc)
	switch scControl & 0x30 {
	case 0x10:
		aad := make([]byte, len(g.aad)+len(apdu))
		aad[0] = scContent
		copy(aad[1:], g.aad[1:])
		copy(aad[len(g.aad):], apdu)

		tag := g.nist.Seal(nil, g.iv[:], nil, aad)
		ret = append(ret[:0], apdu...)
		ret = append(ret, tag...)
		return ret, nil
	case 0x30:
		g.aad[0] = scContent
		ret = g.nist.Seal(ret[:0], g.iv[:], apdu, g.aad)
		return ret, nil
	default:
		return nil, fmt.Errorf("unsupported security control byte: %v", scControl)
	}
}

// GetDecryptorStream implements Gcm.
func (g *cipheringnist) GetDecryptorStream(sc byte, fc uint32, apdu io.Reader) (io.Reader, error) {
	return g.GetDecryptorStream2(sc, sc, fc, apdu)
}

// GetDecryptorStream2 implements Gcm.
func (g *cipheringnist) GetDecryptorStream2(scControl byte, scContent byte, fc uint32, apdu io.Reader) (io.Reader, error) {
	if apdu == nil {
		return nil, fmt.Errorf("apdu is nil")
	}
	switch g.authenticationMechanismId {
	case base.AuthenticationHighGmac, base.AuthenticationHighSha256, base.AuthenticationHighEcdsa:
	default:
		return apdu, nil
	}

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
func (g *cipheringnist) GetEncryptLength(scControl byte, apdu []byte) (int, error) {
	switch g.authenticationMechanismId {
	case base.AuthenticationHighGmac, base.AuthenticationHighSha256, base.AuthenticationHighEcdsa:
	default:
		return len(apdu), nil
	}

	switch scControl & 0x30 {
	case 0x10, 0x30:
		return len(apdu) + GCM_TAG_LENGTH, nil
	}
	return 0, fmt.Errorf("GetEncryptLength not implemented for scControl %02X", scControl)
}

// this is not thread safe at all
func NewCipheringNist(settings *CipheringSettings) (Ciphering, error) { // so only suite 0 right now, just proof of concept
	err := settings.Validate()
	if err != nil {
		return nil, err
	}

	ret := &cipheringnist{
		authenticationMechanismId: settings.AuthenticationMechanismId,
		clientPrivateKey:          settings.ClientPrivateKey,
		serverCertificate:         settings.ServerCertificate,
		systemtitleC:              slices.Clone(settings.ClientTitle),
		ctos:                      slices.Clone(settings.CtoS),
		password:                  slices.Clone(settings.Password),
	}

	switch ret.authenticationMechanismId {
	case base.AuthenticationHighGmac, base.AuthenticationHighSha256, base.AuthenticationHighEcdsa:
		ret.aad = make([]byte, 1+len(settings.AuthenticationKey))
		cr, err := aes.NewCipher(settings.EncryptionKey)
		if err != nil {
			return nil, err
		}
		enc, err := cipher.NewGCMWithTagSize(cr, GCM_TAG_LENGTH)
		if err != nil {
			return nil, err
		}
		ret.nist = enc
		copy(ret.aad[1:], settings.AuthenticationKey)
	}

	return ret, nil
}
