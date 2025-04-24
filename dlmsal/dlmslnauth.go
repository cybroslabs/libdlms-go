package dlmsal

import (
	"encoding/binary"
	"fmt"

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

	// do standard action, dunno if it has to be dedicated or global encrypted ctos packet
	if s.gcm == nil {
		return fmt.Errorf("no gcm set for ciphering")
	}
	// create ctos hash
	e, err := s.gcm.Hash(byte(base.SecurityAuthentication), s.framecounter)
	if err != nil {
		return err
	}

	hashresp := make([]byte, 5+len(e))
	hashresp[0] = byte(base.SecurityAuthentication)
	hashresp[1] = byte(s.framecounter >> 24)
	hashresp[2] = byte(s.framecounter >> 16)
	hashresp[3] = byte(s.framecounter >> 8)
	hashresp[4] = byte(s.framecounter)
	copy(hashresp[5:], e)

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
	if len(aresp) != 5+gcm.GCM_TAG_LENGTH || aresp[0] != byte(base.SecurityAuthentication) {
		return fmt.Errorf("invalid stoc hash response")
	}
	r, err := s.gcm.Verify(aresp[0], binary.BigEndian.Uint32(aresp[1:]), aresp[5:])
	if err != nil {
		return err
	}

	if !r {
		return fmt.Errorf("returned hash mismatch")
	}
	return nil
}
