package dlmsal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/cybroslabs/libdlms-go/base"
	"github.com/cybroslabs/libdlms-go/gcm"
)

func (d *dlmsal) LNAuthentication(checkresp bool) error {
	s := d.settings

	if d.aareres.associationResult != base.AssociationResultAccepted { // sadly this zero is also default value
		return fmt.Errorf("association result not accepted: %v", d.aareres.associationResult)
	}

	switch s.SourceDiagnostic {
	case base.SourceDiagnosticNone:
		return nil
	case base.SourceDiagnosticAuthenticationRequired:
	default:
		return fmt.Errorf("invalid aare response: %v", s.SourceDiagnostic)
	}

	var hashdata []byte
	var hashbuf bytes.Buffer
	switch s.AuthenticationMechanismId {
	case base.AuthenticationNone, base.AuthenticationLow:
		return fmt.Errorf("invalid authentication mechanism: %v", s.AuthenticationMechanismId)
	case base.AuthenticationHigh:
		return fmt.Errorf("high authentication not implemented, this is manufacturer specific mostly")
	case base.AuthenticationHighMD5:
		hashbuf.Write(s.ServerSystemTitle)
		hashbuf.Write(s.password)
		h := md5.Sum(hashbuf.Bytes())
		hashdata = h[:]
	case base.AuthenticationHighSHA1:
		hashbuf.Write(s.ServerSystemTitle)
		hashbuf.Write(s.password)
		h := sha1.Sum(hashbuf.Bytes())
		hashdata = h[:]
	case base.AuthenticationHighGmac:
		if s.gcm == nil { // what about dedicated gmac here?, strange...
			return fmt.Errorf("gcm not set, this is required for gmac authentication")
		}

		// create ctos hash
		e, err := s.gcm.Hash(byte(base.SecurityAuthentication), s.framecounter)
		if err != nil {
			return err
		}

		hashdata = make([]byte, 5+len(e))
		hashdata[0] = byte(base.SecurityAuthentication)
		binary.BigEndian.PutUint32(hashdata[1:], s.framecounter)
		copy(hashdata[5:], e)
		s.framecounter++ // a bit questionable here
	case base.AuthenticationHighSha256:
		hashbuf.Write(s.password)
		hashbuf.Write(s.clientsystemtitle)
		hashbuf.Write(s.ServerSystemTitle)
		hashbuf.Write(s.StoC)
		hashbuf.Write(s.ctos)

		h := sha256.Sum256(hashbuf.Bytes())
		hashdata = h[:]
	case base.AuthenticationHighEcdsa:
		if s.ClientPrivateKey == nil {
			return fmt.Errorf("ecdsa private key not set, this is required for ecdsa authentication")
		}
		hashbuf.Write(s.clientsystemtitle)
		hashbuf.Write(s.ServerSystemTitle)
		hashbuf.Write(s.StoC)
		hashbuf.Write(s.ctos)
		switch s.ClientPrivateKey.Curve.Params().BitSize {
		case 256:
			h := sha256.Sum256(hashbuf.Bytes())
			hashdata = h[:]
		case 384:
			h := sha512.Sum384(hashbuf.Bytes())
			hashdata = h[:]
		default:
			return fmt.Errorf("unsupported curve %v", s.ClientPrivateKey.Curve.Params().BitSize)
		}

		bigr, bifs, err := ecdsa.Sign(rand.Reader, s.ClientPrivateKey, hashdata)
		if err != nil {
			return fmt.Errorf("unable to sign with ecdsa: %w", err)
		}

		hashbuf.Reset()
		hashbuf.Write(bigr.Bytes())
		hashbuf.Write(bifs.Bytes())
		hashdata = hashbuf.Bytes()
	default:
		return fmt.Errorf("invalid authentication mechanism: %v", s.AuthenticationMechanismId)
	}

	data := DlmsData{Tag: TagOctetString, Value: hashdata}
	req := DlmsLNRequestItem{
		ClassId:   15,
		Obis:      DlmsObis{A: 0, B: 0, C: 40, D: 0, E: 0, F: 255},
		Attribute: 1,
		HasAccess: false,
		SetData:   &data,
	}

	adata, err := d.Action(req)
	if err != nil {
		return err
	}
	if adata == nil {
		return fmt.Errorf("no data received from authentication action")
	}
	if !checkresp { // so optimistic
		return nil
	}

	var aresp []byte
	err = Cast(&aresp, *adata)
	if err != nil {
		return err
	}

	hashbuf.Reset()
	switch s.AuthenticationMechanismId {
	case base.AuthenticationHighMD5:
		hashbuf.Write(s.ctos)
		hashbuf.Write(s.password)
		h := md5.Sum(hashbuf.Bytes())
		if !bytes.Equal(aresp, h[:]) {
			return base.ErrInvalidAuthenticationResponse
		}
	case base.AuthenticationHighSHA1:
		hashbuf.Write(s.ctos)
		hashbuf.Write(s.password)
		h := sha1.Sum(hashbuf.Bytes())
		if !bytes.Equal(aresp, h[:]) {
			return base.ErrInvalidAuthenticationResponse
		}
	case base.AuthenticationHighGmac:
		// ok, check response against my own hash
		if len(aresp) != 5+gcm.GCM_TAG_LENGTH || aresp[0] != byte(base.SecurityAuthentication) {
			return fmt.Errorf("invalid stoc hash response")
		}
		r, err := s.gcm.Verify(aresp[0], binary.BigEndian.Uint32(aresp[1:]), aresp[5:])
		if err != nil {
			return err
		}

		if !r {
			return base.ErrInvalidAuthenticationResponse
		}
	case base.AuthenticationHighSha256:
		hashbuf.Write(s.password)
		hashbuf.Write(s.ServerSystemTitle)
		hashbuf.Write(s.clientsystemtitle)
		hashbuf.Write(s.ctos)
		hashbuf.Write(s.StoC)
		h := sha256.Sum256(hashbuf.Bytes())
		if !bytes.Equal(aresp, h[:]) {
			return base.ErrInvalidAuthenticationResponse
		}
	case base.AuthenticationHighEcdsa:
		if s.ServerCertificate == nil {
			return fmt.Errorf("ecdsa server certificate not set, this is required for ecdsa authentication")
		}
		if len(aresp) == 0 || len(aresp)&1 != 0 {
			return fmt.Errorf("invalid ecdsa authmech response length")
		}

		switch pubkey := s.ServerCertificate.PublicKey.(type) {
		case *ecdsa.PublicKey:
			hashbuf.Write(s.ServerSystemTitle)
			hashbuf.Write(s.clientsystemtitle)
			hashbuf.Write(s.ctos)
			hashbuf.Write(s.StoC)

			switch pubkey.Curve.Params().BitSize {
			case 256:
				h := sha256.Sum256(hashbuf.Bytes())
				hashdata = h[:]
			case 384:
				h := sha512.Sum384(hashbuf.Bytes())
				hashdata = h[:]
			default:
				return fmt.Errorf("unsupported curve %v", pubkey.Curve.Params().BitSize)
			}

			var big_r, big_s big.Int
			big_r.SetBytes(aresp[:len(aresp)/2])
			big_s.SetBytes(aresp[len(aresp)/2:])
			if !ecdsa.Verify(pubkey, hashdata, &big_r, &big_s) {
				return base.ErrInvalidAuthenticationResponse
			}
		default:
			return fmt.Errorf("invalid ecdsa server certificate")
		}
	default:
		return fmt.Errorf("invalid authentication mechanism: %v, this is program error", s.AuthenticationMechanismId)
	}
	return nil
}
