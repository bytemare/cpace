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

	Cpace        = "CPace"
	MinSidLength = 16
)

// CPace holds information about the party's state, and offers the protocol functions.
type CPace struct {
	parameters              *Parameters
	SecretScalar            *ecc.Scalar
	EphemeralPublicKeyShare *ecc.Element
	role                    Role
}

// Start creates a secret scalar and uses it to derive a public share with the password and sid.
// If sid is nil, and the caller is Initiator, a new random sid is created.
func (c *CPace) Start(password, sid []byte) (epk *ecc.Element, ssid []byte, err error) {
	ssid, err = checkSid(c.role, sid)
	if err != nil {
		return nil, nil, err
	}

	if c.SecretScalar == nil || c.SecretScalar.IsZero() {
		c.SecretScalar = c.parameters.Group.NewScalar().Random()
	}

	h := slices.Concat(c.parameters.Dsi1, password, ssid, c.parameters.Ida, c.parameters.Idb, c.parameters.Ad)

	m, err := c.parameters.Group.EncodeToGroup([]byte(Cpace+c.parameters.Group.String()), h)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode to group : %w", err)
	}

	c.EphemeralPublicKeyShare = m.Multiply(c.SecretScalar)

	return c.EphemeralPublicKeyShare.Copy(), ssid, nil
}

// Finish uses the peerElement and the internal state to derive and return the session secret.
func (c *CPace) Finish(peerElement *ecc.Element) ([]byte, error) {
	if c.EphemeralPublicKeyShare == nil || c.EphemeralPublicKeyShare.IsIdentity() {
		return nil, ErrNoEphemeralPubKey
	}

	if peerElement == nil {
		return nil, ErrPeerElementNil
	}

	if peerElement.IsIdentity() {
		return nil, ErrPeerElementIdentity
	}

	return c.sessionKey(peerElement)
}

// SetScalar sets the internal secret scalar to s. If s is not successfully deserialized to the set group, this function
// returns an error.
func (c *CPace) SetScalar(s []byte) error {
	if c.SecretScalar == nil {
		c.SecretScalar = c.parameters.Group.NewScalar()
	}

	if err := c.SecretScalar.Decode(s); err != nil {
		return fmt.Errorf("error decoding scalar: %w", err)
	}

	return nil
}

// Scalar returns the internal secret scalar generated in Start(). If Start() hasn't been called or didn't succeed,
// this function returns nil.
func (c *CPace) Scalar() []byte {
	return c.SecretScalar.Encode()
}

func (c *CPace) sessionKey(peerElement *ecc.Element) ([]byte, error) {
	encodedPeerElement := peerElement.Encode()

	k := peerElement.Copy().Multiply(c.SecretScalar)
	if k.IsIdentity() {
		return nil, ErrPeerElementIdentity
	}

	t := c.transcript(k.Encode(), encodedPeerElement)

	return c.parameters.Hash.Hash(t), nil
}

func (c *CPace) transcript(k, peerElement []byte) []byte {
	var epki, epkr []byte

	epk := c.EphemeralPublicKeyShare.Encode()
	switch c.role {
	case Initiator:
		epki = epk
		epkr = peerElement
	case Responder:
		epki = peerElement
		epkr = epk
	}

	tLen := len(c.parameters.Dsi2) + len(k) + len(epk) + len(peerElement)
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
			var out [MinSidLength]byte

			_, _ = rand.Read(out[:])

			return out[:], nil
		}

		return nil, ErrSetupSIDNil
	case l < MinSidLength:
		return nil, ErrSetupSIDTooShort
	}

	return sid, nil
}
