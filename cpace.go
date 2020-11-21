// Package cpace provides an easy to use CPace implementation
package cpace

import (
	"bytes"

	"github.com/bytemare/cryptotools/hashtogroup/group"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/pake"
	"github.com/bytemare/pake/message"
)

const (
	minSidLength = 16
)

// session holds the public, shared, session information
type session struct {
	// role specifies whether the current instance is an initiator or responder
	role pake.Role

	// sid session identifier, must be random and different for each session, and greater or equal than minSidLength bytes
	sid []byte

	// cid channel identifier, holds identities of parties and eventually additional data about the connection
	// cid = idA || idB || AD
	cid []byte
}

// state is the CPace's internal state
type state struct {
	password      []byte
	publicElement []byte
	iSessionKey   []byte

	// Pake engine
	core *pake.Core

	secret group.Scalar

	// Domain separation
	dsi1 []byte
	dsi2 []byte
}

func (c *CPace) publicPoint() error {
	if c.sid == nil {
		return errInternalNoSID
	}

	// If the function has already been called, ensure consistency and keep the value
	if c.publicElement != nil {
		return nil
	}

	// Generate secret scalar
	c.secret = c.core.Crypto.NewScalar().Random()

	// Map the password and parameters to the group
	m := c.core.Crypto.HashToGroup(c.dsi1, c.password, c.sid, c.cid)

	// Generate public share
	c.publicElement = m.Mult(c.secret).Bytes()

	return nil
}

// intermediarySessionKey calculates the secret session key and stores it in internal state
func (c *CPace) intermediarySessionKey(peerElement []byte) error {
	if len(peerElement) == 0 {
		return errPeerElementNil
	}

	if c.publicElement == nil {
		return errInternalNoPublicPoint
	}

	peer, err := c.core.Crypto.NewElement().Decode(peerElement)
	if err != nil {
		return errPeerElementInvalid
	}

	k := peer.Mult(c.secret)
	if k.IsIdentity() {
		return errPeerElementIdentity
	}

	// transcript := c.transcript(peerElement)
	// c.ISessionKey = c.Core.Crypto.HKDF(k.Encode(), transcript, c.dsi2, 0)

	c.buildKey(k.Bytes(), peerElement)

	return err
}

func (c *CPace) buildKey(k, peerElement []byte) {
	ee := make([]byte, 0, len(c.publicElement)+len(peerElement))
	switch c.role {
	case pake.Initiator:
		ee = append(ee, c.publicElement...)
		ee = append(ee, peerElement...)
	case pake.Responder:
		ee = append(ee, peerElement...)
		ee = append(ee, c.publicElement...)
	default:
		panic(errInternalInvalidRole)
	}

	inlen := len(c.dsi2) + len(k) + len(ee)
	in := utils.Concatenate(inlen, c.dsi2, k, ee)

	c.iSessionKey = c.core.Crypto.Hash.Hash(0, in)
}

func (c *CPace) initiate() ([]byte, []byte, error) {
	if err := c.publicPoint(); err != nil {
		return nil, nil, err
	}

	return c.publicElement, c.sid, nil
}

func (c *CPace) response(peerElement, peerSID []byte) ([]byte, error) {
	// The first message should contain the sid in the auth field if it was not set before
	if c.sid == nil {
		if peerSID == nil || len(peerSID) < minSidLength {
			return nil, errInitSIDInvalid
		}

		c.sid = peerSID
	} else if !bytes.Equal(c.sid, peerSID) {
		return nil, errInitSIDDifferent
	}

	// Generate public element
	if err := c.publicPoint(); err != nil {
		return nil, err // this should not happen, since the sid is set before
	}

	// Derive session secret
	if err := c.intermediarySessionKey(peerElement); err != nil {
		return nil, err
	}

	c.core.Expect = message.StageTerminated

	return c.publicElement, nil
}

func (c *CPace) finish(peerElement []byte) error {
	if err := c.intermediarySessionKey(peerElement); err != nil {
		return err
	}

	c.core.Expect = message.StageTerminated

	return nil
}

// transcript returns the protocol's transcript given the peer element
//func (c *CPace) transcript(peerElement []byte) []byte {
//	transcript := make([]byte, 0, minSidLength+2*pointLength)
//	transcript = append(transcript, c.sid...)
//
//	switch c.role {
//	case pake.Initiator:
//		transcript = append(transcript, c.publicElement...)
//		transcript = append(transcript, peerElement...)
//	case pake.Responder:
//		transcript = append(transcript, peerElement...)
//		transcript = append(transcript, c.publicElement...)
//	default:
//		panic(errInternalInvalidRole)
//	}
//
//	return transcript
//}
