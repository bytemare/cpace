package cpace

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/utils"
)

// Role in the protocol.
type Role bool

const (
	// Initiator is the role that initiates (starts) the protocol.
	Initiator Role = true

	// Responder is the role that receives the request.
	Responder Role = false

	cpace        = "CPace"
	minSidLength = 16
)

type state struct {
	epk    []byte
	scalar group.Scalar
}

// CPace holds information about the party's state, and offers the protocol functions.
type CPace struct {
	role  Role
	group group.Group
	info  Info
	state
}

func (c *CPace) sessionKey(peerElement []byte) ([]byte, error) {
	if len(c.epk) == 0 {
		return nil, errNoEphemeralPubKey
	}

	if len(peerElement) == 0 {
		return nil, errPeerElementNil
	}

	peer, err := c.group.NewElement().Decode(peerElement)
	if err != nil {
		return nil, errPeerElementInvalid
	}

	k := peer.Mult(c.scalar)
	if k.IsIdentity() {
		return nil, errPeerElementIdentity
	}

	t := c.transcript(k.Bytes(), peerElement)
	h := c.info.Hash.Get()

	return h.Hash(h.OutputSize(), t), err
}

func (c *CPace) transcript(k, peerElement []byte) []byte {
	var epki, epkr []byte

	switch c.role {
	case Initiator:
		epki = c.epk
		epkr = peerElement
	case Responder:
		epki = peerElement
		epkr = c.epk
	}

	tLen := len(c.info.Dsi2) + len(k) + len(c.epk) + len(peerElement)

	return utils.Concatenate(tLen, c.info.Dsi2, k, epki, epkr)
}

// checkSid verifies the session id, and generates one for the initiator if none provided.
func checkSid(role Role, sid []byte) ([]byte, error) {
	switch l := len(sid); {
	case l == 0:
		// If none is given for the Responder, we'll take it from the initiator's first message
		if role == Initiator {
			return utils.RandomBytes(minSidLength), nil
		}

		return nil, errSetupSIDNil
	case l < minSidLength:
		return nil, errSetupSIDTooShort
	}

	return sid, nil
}

// Start creates a secret scalar and uses it to derive a public share with the password and sid.
// If sid is nil, and the caller is Initiator, a new random sid is created.
func (c *CPace) Start(password, sid []byte) (epk, ssid []byte, err error) {
	sid, err = checkSid(c.role, sid)
	if err != nil {
		return nil, nil, err
	}

	if c.scalar == nil {
		c.scalar = c.group.NewScalar().Random()
	}

	m := c.group.HashToGroup(c.info.Dsi1, password, sid, c.info.Ida, c.info.Idb, c.info.Ad)
	c.epk = m.Mult(c.scalar).Bytes()

	return c.epk, sid, nil
}

// Finish uses the peerElement and the internal state to derive and return the session secret.
func (c *CPace) Finish(peerElement []byte) ([]byte, error) {
	return c.sessionKey(peerElement)
}

// SetScalar sets the internal secret scalar to s. If s is not successfully deserialized to the set group, this function
// returns an error.
func (c *CPace) SetScalar(s []byte) (err error) {
	c.scalar, err = c.group.NewScalar().Decode(s)
	return err
}

// Scalar returns the internal secret scalar generated in Start(). If Start() hasn't been called or didn't succeed,
// this function returns nil.
func (c *CPace) Scalar() []byte {
	return c.scalar.Bytes()
}
