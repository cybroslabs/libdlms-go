package dlmsal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/cybroslabs/libdlms-go/base"
)

// no streaming yet, this is... damn that
func ecdsasign(origin, recipient, content []byte, privkey *ecdsa.PrivateKey) ([]byte, error) { // signature only for now, returns whole signet pdu with tag and so on
	var transid [3]byte
	_, _ = rand.Read(transid[:])
	var ret bytes.Buffer
	ret.WriteByte(byte(base.TagGeneralSigning))
	encodelength(&ret, uint(len(transid)))
	ret.Write(transid[:])
	encodelength(&ret, uint(len(origin)))
	ret.Write(origin)
	encodelength(&ret, uint(len(recipient)))
	ret.Write(recipient)
	ret.WriteByte(0) // no datetime
	ret.WriteByte(0) // no other information
	encodelength(&ret, uint(len(content)))
	ret.Write(content)

	var hash []byte
	switch privkey.Curve.Params().BitSize {
	case 256:
		h := sha256.Sum256(ret.Bytes()[1:])
		hash = h[:]
	case 384:
		h := sha512.Sum384(ret.Bytes()[1:])
		hash = h[:]
	default:
		return nil, fmt.Errorf("unsupported curve %v", privkey.Curve.Params().BitSize)
	}
	sign_r, sign_s, err := ecdsa.Sign(rand.Reader, privkey, hash)
	if err != nil {
		return nil, err
	}
	ret.Write(sign_r.Bytes())
	ret.Write(sign_s.Bytes())
	return ret.Bytes(), nil
}
