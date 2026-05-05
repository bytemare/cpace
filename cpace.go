// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package cpace

import (
	"crypto/rand"
	"fmt"
	"slices"

	"github.com/bytemare/ecc"
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

// CPace holds information about the party's state, and offers the protocol functions.
type CPace struct {
	parameters *Parameters
	scalar     *ecc.Scalar
	epk        []byte
	role       Role
	group      ecc.Group
}

// Start creates a secret scalar and uses it to derive a public share with the password and sid.
// If sid is nil, and the caller is Initiator, a new random sid is created.
func (c *CPace) Start(password, sid []byte) (epk, ssid []byte, err error) {
	ssid, err = checkSid(c.role, sid)
	if err != nil {
		return nil, nil, err
	}

	if c.scalar == nil || c.scalar.IsZero() {
		c.scalar = c.group.NewScalar().Random()
	}

	h := slices.Concat(c.parameters.Dsi1, password, sid, c.parameters.Ida, c.parameters.Idb, c.parameters.Ad)
	m := c.group.HashToGroup([]byte(cpace+c.parameters.Group.String()), h)
	c.epk = m.Multiply(c.scalar).Encode()

	return c.epk, ssid, nil
}

// Finish uses the peerElement and the internal state to derive and return the session secret.
func (c *CPace) Finish(peerElement []byte) ([]byte, error) {
	if len(c.epk) == 0 {
		return nil, errNoEphemeralPubKey
	}

	if len(peerElement) == 0 {
		return nil, errPeerElementNil
	}

	return c.sessionKey(peerElement)
}

// SetScalar sets the internal secret scalar to s. If s is not successfully deserialized to the set group, this function
// returns an error.
func (c *CPace) SetScalar(s []byte) error {
	if c.scalar == nil {
		c.scalar = c.group.NewScalar()
	}

	if err := c.scalar.Decode(s); err != nil {
		return fmt.Errorf("error decoding scalar: %w", err)
	}

	return nil
}

// Scalar returns the internal secret scalar generated in Start(). If Start() hasn't been called or didn't succeed,
// this function returns nil.
func (c *CPace) Scalar() []byte {
	return c.scalar.Encode()
}

func (c *CPace) sessionKey(peerElement []byte) ([]byte, error) {
	peer := c.group.NewElement()
	if err := peer.Decode(peerElement); err != nil {
		return nil, errPeerElementInvalid
	}

	k := peer.Multiply(c.scalar)
	if k.IsIdentity() {
		return nil, errPeerElementIdentity
	}

	t := c.transcript(k.Encode(), peerElement)

	return c.parameters.Hash.Hash(t), nil
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

	tLen := len(c.parameters.Dsi2) + len(k) + len(c.epk) + len(peerElement)
	out := make([]byte, tLen)
	copy(out, c.parameters.Dsi2)
	copy(out[len(c.parameters.Dsi2):], k)
	copy(out[len(c.parameters.Dsi2)+len(k):], epki)
	copy(out[len(c.parameters.Dsi2)+len(k)+len(epki):], epkr)

	return out
}

// checkSid verifies the session id, and generates one for the initiator if none provided.
func checkSid(role Role, sid []byte) ([]byte, error) {
	switch l := len(sid); {
	case l == 0:
		// If none is given for the Responder, we'll take it from the initiator's first message
		if role == Initiator {
			var out [minSidLength]byte

			_, _ = rand.Read(out[:])

			return out[:], nil
		}

		return nil, errSetupSIDNil
	case l < minSidLength:
		return nil, errSetupSIDTooShort
	}

	return sid, nil
}
