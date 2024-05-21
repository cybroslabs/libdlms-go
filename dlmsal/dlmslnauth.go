package dlmsal

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cybroslabs/libdlms-go/gcm"
)

func (d *dlmsal) LNAuthentication(checkresp bool) error {
	s := d.settings

	if d.aareres.AssociationResult != AssociationResultAccepted { // sadly this zero is also default value
		return fmt.Errorf("association result not accepted: %v", d.aareres.AssociationResult)
	}

	switch s.SourceDiagnostic {
	case SourceDiagnosticNone:
		return nil
	case SourceDiagnosticAuthenticationRequired:
	default:
		return fmt.Errorf("invalid aare response: %v", s.SourceDiagnostic)
	}

	// do standard action, dunno if it has to be dedicated or global encrypted ctos packet
	if s.gcm == nil {
		return fmt.Errorf("no gcm set for ciphering")
	}
	// create ctos hash
	e, err := s.gcm.Encrypt(d.cryptbuffer, byte(SecurityAuthentication), s.framecounter, s.systemtitle, s.StoC)
	if err != nil {
		return err
	}
	if len(e) < gcm.GCM_TAG_LENGTH {
		return fmt.Errorf("encrypted data too short")
	}

	hashresp := make([]byte, 5+gcm.GCM_TAG_LENGTH)
	hashresp[0] = byte(SecurityAuthentication)
	hashresp[1] = byte(s.framecounter >> 24)
	hashresp[2] = byte(s.framecounter >> 16)
	hashresp[3] = byte(s.framecounter >> 8)
	hashresp[4] = byte(s.framecounter)
	copy(hashresp[5:], e[len(e)-gcm.GCM_TAG_LENGTH:])

	data := DlmsData{Tag: TagOctetString, Value: hashresp}
	req := DlmsLNRequestItem{
		ClassId:   15,
		Obis:      DlmsObis{A: 0, B: 0, C: 40, D: 0, E: 0, F: 255},
		Attribute: 1,
		HasAccess: false,
		SetData:   &data}

	s.framecounter++
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
	// ok, check response against my own hash
	if len(aresp) != 5+gcm.GCM_TAG_LENGTH || aresp[0] != byte(SecurityAuthentication) {
		return fmt.Errorf("invalid stoc hash response")
	}
	r, err := s.gcm.Encrypt(d.cryptbuffer, aresp[0], binary.BigEndian.Uint32(aresp[1:]), d.aareres.SystemTitle, s.CtoS)
	if err != nil {
		return err
	}
	if len(r) < gcm.GCM_TAG_LENGTH {
		return fmt.Errorf("probably programatic error")
	}

	if bytes.Equal(aresp[5:], r[len(r)-gcm.GCM_TAG_LENGTH:]) {
		return nil
	}

	return fmt.Errorf("returned hash mismatch")
}
