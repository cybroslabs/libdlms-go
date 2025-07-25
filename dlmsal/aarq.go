package dlmsal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/cybroslabs/libdlms-go/base"
)

type initiateResponse struct {
	negotiatedQualityOfService byte
	serverMaxReceivePduSize    uint16
	vAAddress                  int16
}

type confirmedServiceErrorTag byte

const (
	TagErrInitiateError confirmedServiceErrorTag = 1
	TagErrRead          confirmedServiceErrorTag = 5
	TagErrWrite         confirmedServiceErrorTag = 6
)

type serviceErrorTag byte

const (
	TagErrApplicationReference serviceErrorTag = 0
	TagErrHardwareResource     serviceErrorTag = 1
	TagErrVdeStateError        serviceErrorTag = 2
	TagErrService              serviceErrorTag = 3
	TagErrDefinition           serviceErrorTag = 4
	TagErrAccess               serviceErrorTag = 5
	TagErrInitiate             serviceErrorTag = 6
	TagErrLoadDataSet          serviceErrorTag = 7
	TagErrTask                 serviceErrorTag = 9
	TagErrOtherError           serviceErrorTag = 10
)

type confirmedServiceError struct {
	ConfirmedServiceError confirmedServiceErrorTag
	ServiceError          serviceErrorTag
	Value                 byte
}

type aaretag struct {
	tag  byte
	data []byte
}

type aaResponse struct {
	applicationContextName base.ApplicationContext
	initiateResponse       *initiateResponse
	confirmedServiceError  *confirmedServiceError
}

func putappctxname(dst *bytes.Buffer, settings *DlmsSettings) {
	// not so exactly correct things, but for speed sake
	dst.WriteByte(base.BERTypeContext | base.BERTypeConstructed | base.PduTypeApplicationContextName)
	dst.Write([]byte{0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01})
	dst.WriteByte(byte(settings.ApplicationContext))
}

func putmechname(dst *bytes.Buffer, settings *DlmsSettings) {
	if settings.AuthenticationMechanismId == base.AuthenticationNone {
		return
	}
	encodetag(dst, base.BERTypeContext|base.PduTypeSenderAcseRequirements, []byte{0x07, 0x80})
	dst.WriteByte(base.BERTypeContext | base.PduTypeMechanismName)
	dst.Write([]byte{0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02})
	dst.WriteByte(byte(settings.AuthenticationMechanismId))
}

func putsecvalues(dst *bytes.Buffer, settings *DlmsSettings) {
	if settings.AuthenticationMechanismId == base.AuthenticationNone {
		return
	}
	encodetag2(dst, base.BERTypeContext|base.BERTypeConstructed|base.PduTypeCallingAuthenticationValue, 0x80, settings.password)
}

func putsystitle(dst *bytes.Buffer, settings *DlmsSettings) {
	switch settings.AuthenticationMechanismId {
	case base.AuthenticationHighGmac, base.AuthenticationHighSha256, base.AuthenticationHighEcdsa:
		encodetag2(dst, base.BERTypeContext|base.BERTypeConstructed|base.PduTypeCallingAPTitle, 0x04, settings.clientsystemtitle)
	}
}

func putuserid(dst *bytes.Buffer, settings *DlmsSettings) {
	if settings.UserId == nil {
		return
	}
	dst.WriteByte(base.BERTypeContext | base.BERTypeConstructed | base.PduTypeCallingAEInvocationID)
	dst.WriteByte(3)
	dst.WriteByte(2)
	dst.WriteByte(1)
	dst.WriteByte(*settings.UserId)
}

func (d *dlmsal) createxdlms(dst *bytes.Buffer) (err error) {
	s := d.settings
	var xdlms []byte
	var subxdlms []byte
	if s.dedcipher != nil {
		xdlms = make([]byte, 15+len(s.dedicatedkey))
		xdlms[0] = byte(base.TagInitiateRequest)
		xdlms[1] = 0x01
		xdlms[2] = byte(len(s.dedicatedkey))
		copy(xdlms[3:], s.dedicatedkey)
		subxdlms = xdlms[3+len(s.dedicatedkey):]
	} else {
		xdlms = make([]byte, 14)
		xdlms[0] = byte(base.TagInitiateRequest)
		xdlms[1] = 0x00
		subxdlms = xdlms[2:]
	}
	subxdlms[0] = 0x00
	subxdlms[1] = 0x00
	subxdlms[2] = 0x06
	subxdlms[3] = 0x5f
	subxdlms[4] = 0x1f
	subxdlms[5] = 0x04
	// put conform
	binary.BigEndian.PutUint32(subxdlms[6:], uint32(s.ConformanceBlock))
	subxdlms[10] = byte(s.MaxPduRecvSize >> 8) // no limit in maximum received apdu length
	subxdlms[11] = byte(s.MaxPduRecvSize)

	if !s.DontEncryptUserInformation {
		switch s.AuthenticationMechanismId {
		case base.AuthenticationHighGmac, base.AuthenticationHighSha256, base.AuthenticationHighEcdsa: // encrypt this
			xdlms, err = d.encryptpacket(byte(base.TagGloInitiateRequest), xdlms, false)
		}
	}
	encodetag2(dst, base.BERTypeContext|base.BERTypeConstructed|base.PduTypeUserInformation, 0x04, xdlms)
	return
}

func (d *dlmsal) encodeaarq() (out []byte, outnosec []byte, err error) {
	var buf bytes.Buffer
	var content bytes.Buffer
	s := d.settings

	putappctxname(&content, s)
	putsystitle(&content, s)
	putuserid(&content, s)
	putmechname(&content, s)
	st := content.Len()
	putsecvalues(&content, s)
	en := content.Len()
	err = d.createxdlms(&content)
	if err != nil {
		return
	}

	encodetag(&buf, byte(base.TagAARQ), content.Bytes())
	out = buf.Bytes()
	outnosec = slices.Clone(out)
	clear(outnosec[st:en])
	return
}

func decodeaare(src []byte, tmp *tmpbuffer) ([]aaretag, error) {
	ret := make([]aaretag, 0, 20)
	for len(src) > 0 {
		tag, l, data, err := decodetag(src, tmp)
		if err != nil {
			return nil, err
		}
		ret = append(ret, aaretag{tag: tag, data: data})
		src = src[l:]
	}
	return ret, nil
}

func parseApplicationContextName(tag aaretag) (out base.ApplicationContext, err error) {
	if len(tag.data) != 9 {
		err = fmt.Errorf("invalid A1 tag length")
		return
	}
	rsp := []byte{0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01}
	if !bytes.Equal(tag.data[:8], rsp) {
		err = fmt.Errorf("invalid A1 tag content")
		return
	}
	out = base.ApplicationContext(tag.data[8])
	return
}

func parseAssociationResult(tag aaretag) (out base.AssociationResult, err error) {
	if len(tag.data) != 3 {
		err = fmt.Errorf("invalid A2 tag length")
		return
	}
	rsp := []byte{0x02, 0x01}
	if !bytes.Equal(tag.data[:2], rsp) {
		err = fmt.Errorf("invalid A2 tag content")
		return
	}
	out = base.AssociationResult(tag.data[2])
	return
}

func parseAssociateSourceDiagnostic(tag aaretag) (out base.SourceDiagnostic, err error) {
	if len(tag.data) != 5 {
		err = fmt.Errorf("invalid A3 tag length")
		return
	}
	rsp := []byte{0x03, 0x02, 0x01}
	if !bytes.Equal(tag.data[1:4], rsp) {
		err = fmt.Errorf("invalid A3 tag content")
		return
	}
	out = base.SourceDiagnostic(tag.data[4])
	return
}

func parseAPTitle(tag aaretag, tmp *tmpbuffer) (out []byte, err error) {
	if len(tag.data) < 2 {
		return nil, fmt.Errorf("invalid A4 tag length")
	}
	t, _, d, err := decodetag(tag.data, tmp)
	if err != nil {
		return nil, err
	}
	if t != 0x04 {
		return nil, fmt.Errorf("invalid A4 tag content")
	}
	out = slices.Clone(d)
	return
}

func (d *dlmsal) parseCalledAEInvocationID(tag aaretag) error {
	if len(tag.data) < 2 {
		return fmt.Errorf("invalid A5 tag length")
	}
	// parse inner tag
	t, _, _, err := decodetag(tag.data, &d.tmpbuffer)
	if err != nil {
		return err
	}

	d.logf("parseCalledAEInvocationID, for now, not used much: %02x %02x", tag.tag, t)
	return nil
}

func parseSenderAcseRequirements(tag aaretag, tmp *tmpbuffer) (stoc []byte, err error) {
	if len(tag.data) < 2 {
		return nil, fmt.Errorf("invalid AA tag length")
	}
	t, _, d, err := decodetag(tag.data, tmp)
	if err != nil {
		return nil, err
	}
	if t != 0x80 {
		return nil, fmt.Errorf("invalid AA tag content")
	}
	stoc = slices.Clone(d)
	return
}

func parseAcsefield(tag aaretag) error {
	if len(tag.data) != 2 {
		return fmt.Errorf("invalid 88 tag length")
	}
	if tag.data[0] != 0x07 || tag.data[1] != 0x80 {
		return fmt.Errorf("invalid 88 tag content")
	}
	return nil
}

func parseAEInvocationID(tag aaretag) (out base.Authentication, err error) {
	if len(tag.data) != 7 {
		err = fmt.Errorf("invalid 89 tag length")
		return
	}
	if tag.data[0] != 0x60 || tag.data[1] != 0x85 || tag.data[2] != 0x74 || tag.data[3] != 0x05 || tag.data[4] != 0x08 || tag.data[5] != 0x02 {
		err = fmt.Errorf("invalid 89 tag content")
		return
	}
	out = base.Authentication(tag.data[6])
	return
}

func (al *dlmsal) parseUserInformation(tag aaretag) (ir *initiateResponse, cse *confirmedServiceError, err error) {
	if len(tag.data) < 6 {
		err = fmt.Errorf("invalid BE tag length")
		return
	}
	t, _, d, err := decodetag(tag.data, &al.tmpbuffer)
	if err != nil {
		return nil, nil, err
	}
	if t != 0x04 {
		return nil, nil, fmt.Errorf("invalid BE tag content")
	}
	return al.parseUserInformationtag(d)
}

func (al *dlmsal) parseUserInformationtag(d []byte) (ir *initiateResponse, cse *confirmedServiceError, err error) {
	switch base.CosemTag(d[0]) {
	case base.TagInitiateResponse:
		iir, err := al.decodeInitiateResponse(d[1:])
		return &iir, nil, err
	case base.TagConfirmedServiceError:
		cse, err := decodeConfirmedServiceError(d[1:])
		return nil, &cse, err
	case base.TagGloConfirmedServiceError: // artifical service error for now, not decoding inside of it
		return nil, nil, fmt.Errorf("TagGloConfirmedServiceError returned")
	case base.TagGloInitiateResponse, base.TagGeneralGloCiphering:
		decxdlms, err := al.decryptpacket(d, false)
		if err != nil {
			return nil, nil, err
		}
		return al.parseUserInformationtag(decxdlms)
	}

	err = fmt.Errorf("unexpected user information tag %02x", d[0])
	return
}

func (al *dlmsal) decodeInitiateResponse(src []byte) (out initiateResponse, err error) {
	if len(src) < 13 {
		if len(src) == 12 && cap(src) > 12 { // some units can return this shit, underlying array should be big enough to accomodate additional byte
			src = src[:13] // this hack wont work if 0xbe tag is not the last one, ok, usually is the last one
		} else {
			err = fmt.Errorf("invalid initial response length")
			return
		}
	}

	if src[0] == 0x01 {
		out.negotiatedQualityOfService = src[1]
		src = src[2:]
	} else {
		src = src[1:]
	}

	if src[0] != base.DlmsVersion {
		err = fmt.Errorf("wrong dlms version")
		return
	}

	if !bytes.Equal(src[1:5], []byte{0x5F, 0x1F, 0x04, 0x00}) {
		err = fmt.Errorf("invalid initial response content")
		return
	}

	al.settings.ReturnedConformanceBlock = binary.BigEndian.Uint32(src[4:8])
	al.settings.computedconf = al.settings.ConformanceBlock & al.settings.ReturnedConformanceBlock
	out.serverMaxReceivePduSize = binary.BigEndian.Uint16(src[8:10])
	out.vAAddress = int16(binary.BigEndian.Uint16(src[10:12]))
	return
}

func decodeConfirmedServiceError(src []byte) (out confirmedServiceError, err error) {
	if len(src) < 3 {
		err = fmt.Errorf("invalid service error length")
		return
	}

	out.ConfirmedServiceError = confirmedServiceErrorTag(src[0])
	out.ServiceError = serviceErrorTag(src[1])
	out.Value = src[2]
	return
}
