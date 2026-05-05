// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package cpace

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/bytemare/ecc"
	"github.com/bytemare/hash"
)

const (
	dsiFormat      = "%s%s-%d" // "CPace[Group]-[i]"
	encodingLength = 1
)

// Parameters identifies the components of a Ciphersuite.
type Parameters struct {
	*Info `json:"info"`
	Group ecc.Group `json:"group"`
	Hash  hash.Hash `json:"hash"`
}

// Init initialises the parameters with information relative to the communication peers, and returns p.
// This enables pre-computation of the common initialization state between the peers and ready-to-use offline storage.
func (p *Parameters) Init(ida, idb, ad []byte) *Parameters {
	p.Info = &Info{
		Ida:  ida,
		Idb:  idb,
		Ad:   ad,
		Dsi1: fmt.Appendf(nil, dsiFormat, cpace, p.Group, 1),
		Dsi2: fmt.Appendf(nil, dsiFormat, cpace, p.Group, 2),
	}

	return p
}

// Initiator returns a pointer to a CPace structure for the protocol's initiator role.
func (p *Parameters) Initiator() *CPace {
	return p.new(Initiator)
}

// Responder returns a pointer to a CPace structure for the protocol's responder role.
func (p *Parameters) Responder() *CPace {
	return p.new(Responder)
}

// Serialize returns a byte string serialization of p.
func (p *Parameters) Serialize() []byte {
	var i []byte
	if p.Info == nil {
		i = nil
	} else {
		i = p.Info.Serialize()
	}

	return slices.Concat([]byte{byte(p.Group), byte(p.Hash)}, i)
}

func (p *Parameters) new(role Role) *CPace {
	return &CPace{
		role:       role,
		group:      p.Group,
		parameters: p,
		scalar:     nil,
		epk:        nil,
	}
}

// DeserializeParameters attempts to decode input into a Parameter structure.
// Out-of-bounds panics are recovered from and returned as errors with field specification.
func DeserializeParameters(input []byte) (*Parameters, error) {
	if len(input) < 2 {
		return nil, errEncodingShort
	}

	g := input[0]
	if !ecc.Group(g).Available() {
		return nil, errEncodingCiphersuite
	}

	h := input[1]
	if !hash.Hash(h).Available() {
		return nil, errEncodingHash
	}

	i, err := DeserializeInfo(input[2:])
	if err != nil {
		return nil, err
	}

	return &Parameters{
		Group: ecc.Group(g),
		Hash:  hash.Hash(h),
		Info:  i,
	}, nil
}

// Info holds the CPace initialization state. It can be pre-computed, stored, and reused.
type Info struct {
	// Ida is the initiator's identifier.
	Ida []byte `json:"ida"`

	// Idb is the responder's identifier.
	Idb []byte `json:"idb"`

	// Ad is additional data to be used for the channel identifier.
	Ad []byte `json:"ad"`

	// Domain separation identifiers.
	Dsi1 []byte `json:"dsi1"`
	Dsi2 []byte `json:"dsi2"`
}

// Serialize returns a byte string serialization of i.
func (i *Info) Serialize() []byte {
	// need bounds check on length of these arrays. Wait for definition.
	return slices.Concat(
		serialize(i.Ida),
		serialize(i.Idb),
		serialize(i.Ad),
		serialize(i.Dsi1),
		serialize(i.Dsi2),
	)
}

func serialize(input []byte) []byte {
	var prefix [2]byte

	out := make([]byte, len(input)+1)
	binary.BigEndian.PutUint16(prefix[:], uint16(len(input)))
	out[0] = prefix[1:2][0]
	copy(out[1:], input)

	return out
}

// os2ip Octet Stream to Integer Primitive on maximum 4 bytes / 32 bits.
func os2ip(input []byte) int {
	switch len(input) {
	case 0:
		panic(ErrInputEmpty)
	case 1:
		b := []byte{0, input[0]}
		return int(binary.BigEndian.Uint16(b))
	case 2:
		return int(binary.BigEndian.Uint16(input))
	case 3:
		b := append([]byte{0}, input...)
		return int(binary.BigEndian.Uint32(b))
	case 4:
		return int(binary.BigEndian.Uint32(input))
	default:
		panic(ErrInputTooLarge)
	}
}

func deserialize(in []byte, start int) (b []byte, offset int, err error) {
	defer func() {
		if recover() != nil {
			err = errDecodingBounds
		}
	}()

	step := start + encodingLength
	l := os2ip(in[start:step])
	b = in[step : step+l]

	return b, step + l, err
}

// DeserializeInfo attempts to decode input into an Info structure.
// Out-of-bounds panics are recovered from and returned as errors with field specification.
// Nil input returns nil Info pointer without error.
func DeserializeInfo(input []byte) (*Info, error) {
	if len(input) == 0 {
		return nil, ErrInputEmpty
	}

	offset := 0

	ida, offset, err := deserialize(input, offset)
	if err != nil {
		return nil, fmt.Errorf("error decoding info - failed at offset %d (%s): %w", offset, "ida", err)
	}

	idb, offset, err := deserialize(input, offset)
	if err != nil {
		return nil, fmt.Errorf("error decoding info - failed at offset %d (%s): %w", offset, "idb", err)
	}

	ad, offset, err := deserialize(input, offset)
	if err != nil {
		return nil, fmt.Errorf("error decoding info - failed at offset %d (%s): %w", offset, "ad", err)
	}

	dsi1, offset, err := deserialize(input, offset)
	if err != nil {
		return nil, fmt.Errorf("error decoding info - failed at offset %d (%s): %w", offset, "dsi1", err)
	}

	dsi2, offset, err := deserialize(input, offset)
	if err != nil {
		return nil, fmt.Errorf("error decoding info - failed at offset %d (%s): %w", offset, "dsi2", err)
	}

	return &Info{
		Ida:  ida,
		Idb:  idb,
		Ad:   ad,
		Dsi1: dsi1,
		Dsi2: dsi2,
	}, nil
}
