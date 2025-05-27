package dlmsal

import (
	"encoding/binary"
	"fmt"

	"github.com/cybroslabs/libdlms-go/base"
	"github.com/cybroslabs/libdlms-go/ciphering"
)

func (d *dlmsal) LNAuthentication(checkresp bool) (err error) {
	s := d.settings

	if s.AssociationResult != base.AssociationResultAccepted { // sadly this zero is also default value
		return fmt.Errorf("association result not accepted: %v", s.AssociationResult)
	}

	switch s.SourceDiagnostic {
	case base.SourceDiagnosticNone:
		return nil
	case base.SourceDiagnosticAuthenticationRequired:
	default:
		return fmt.Errorf("invalid aare response: %v", s.SourceDiagnostic)
	}

	var hashdata []byte
	switch s.AuthenticationMechanismId {
	case base.AuthenticationNone, base.AuthenticationLow:
		return fmt.Errorf("invalid authentication mechanism: %v", s.AuthenticationMechanismId)
	case base.AuthenticationHigh:
		return fmt.Errorf("high authentication not implemented, this is manufacturer specific mostly")
	case base.AuthenticationHighMD5, base.AuthenticationHighSHA1, base.AuthenticationHighSha256, base.AuthenticationHighEcdsa:
		if s.cipher == nil { // what about dedicated gmac here?, strange...
			return fmt.Errorf("cipher not set, this is required for gmac authentication")
		}
		hashdata, err = s.cipher.Hash(byte(base.SecurityAuthentication), s.framecounter)
	case base.AuthenticationHighGmac:
		if s.cipher == nil { // what about dedicated gmac here?, strange...
			return fmt.Errorf("cipher not set, this is required for gmac authentication")
		}

		sc := base.SecurityAuthentication | (s.Security & base.SecuritySuiteMask)
		// create ctos hash
		hashdata, err = s.cipher.Hash(byte(sc), s.framecounter)
		if err != nil {
			return
		}

		hashdata2 := make([]byte, 5+len(hashdata))
		hashdata2[0] = byte(sc)
		binary.BigEndian.PutUint32(hashdata2[1:], s.framecounter)
		copy(hashdata2[5:], hashdata)
		s.framecounter++ // a bit questionable here
		hashdata = hashdata2
	default:
		return fmt.Errorf("invalid authentication mechanism: %v", s.AuthenticationMechanismId)
	}
	if err != nil {
		return
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

	var result bool
	switch s.AuthenticationMechanismId {
	case base.AuthenticationHighMD5, base.AuthenticationHighSHA1, base.AuthenticationHighSha256, base.AuthenticationHighEcdsa:
		result, err = s.cipher.Verify(byte(base.SecurityAuthentication), s.framecounter, aresp)
	case base.AuthenticationHighGmac:
		// ok, check response against my own hash
		if len(aresp) != 5+ciphering.GCM_TAG_LENGTH || aresp[0]&^byte(base.SecuritySuiteMask) != byte(base.SecurityAuthentication) {
			return fmt.Errorf("invalid stoc hash response")
		}
		result, err = s.cipher.Verify(aresp[0], binary.BigEndian.Uint32(aresp[1:]), aresp[5:])
	default:
		return fmt.Errorf("invalid authentication mechanism: %v, this is program error", s.AuthenticationMechanismId)
	}

	if !result {
		return base.ErrInvalidAuthenticationResponse
	}
	return
}
