package cpace

import (
	"fmt"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/utils"
)

const (
	dsiFormat = "%s%s-%d" // "CPace[Group]-[i]"
	encodingLength = 1
)

// Parameters identifies the components of a Ciphersuite.
type Parameters struct {
	Group ciphersuite.Identifier `json:"group"`
	Hash  hash.Identifier        `json:"hash"`
	*Info `json:"info"`
}

// Init initialises the parameters with information relative to the communication peers, and returns p.
// This enables pre-computation of the common initialization state between the peers and ready-to-use offline storage.
func (p *Parameters) Init(ida, idb, ad []byte) *Parameters {
	p.Info = &Info{
		Ida:  ida,
		Idb:  idb,
		Ad:   ad,
		Dsi1: []byte(fmt.Sprintf(dsiFormat, cpace, p.Group, 1)),
		Dsi2: []byte(fmt.Sprintf(dsiFormat, cpace, p.Group, 2)),
	}

	return p
}

func (p *Parameters) new(role Role) *CPace {
	h2gDST := []byte(cpace + p.Group.String())

	return &CPace{
		role:       role,
		group:      p.Group.Get(h2gDST),
		parameters: p,
	}
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

	return utils.Concatenate(0, []byte{byte(p.Group), byte(p.Hash)}, i)
}

// DeserializeParameters attempts to decode input into a Parameter structure.
// Out-of-bounds panics are recovered from and returned as errors with field specification.
func DeserializeParameters(input []byte) (*Parameters, error) {
	if len(input) < 2 {
		return nil, errEncodingShort
	}

	g := input[0]
	if !ciphersuite.Identifier(g).Available() {
		return nil, errEncodingCiphersuite
	}

	h := input[1]
	if !hash.Identifier(h).Available() {
		return nil, errEncodingHash
	}

	i, err := DeserializeInfo(input[2:])
	if err != nil {
		return nil, err
	}

	return &Parameters{
		Group: ciphersuite.Identifier(g),
		Hash:  hash.Identifier(h),
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
	// todo: bounds check on length of these arrays. Wait for definition.
	return utils.Concatenate(0,
		serialize(i.Ida, encodingLength),
		serialize(i.Idb, encodingLength),
		serialize(i.Ad, encodingLength),
		serialize(i.Dsi1, encodingLength),
		serialize(i.Dsi2, encodingLength),
	)
}

func serialize(input []byte, length int) []byte {
	return append(encoding.I2OSP(len(input), length), input...)
}

func deserialize(in []byte, start, length int) (b []byte, offset int, err error) {
	defer func() {
		if recover() != nil {
			err = errDecodingBounds
		}
	}()

	step := start + length
	l := encoding.OS2IP(in[start:step])
	b = in[step : step+l]

	return b, step + l, nil
}

// DeserializeInfo attempts to decode input into an Info structure.
// Out-of-bounds panics are recovered from and returned as errors with field specification.
// Nil input returns nil Info pointer without error.
func DeserializeInfo(input []byte) (*Info, error) {
	if len(input) == 0 {
		return nil, nil
	}

	offset := 0

	ida, offset, err := deserialize(input, offset, encodingLength)
	if err != nil {
		return nil, fmt.Errorf("error decoding info - failed at offset %d (%s): %w", offset, "ida", err)
	}

	idb, offset, err := deserialize(input, offset, encodingLength)
	if err != nil {
		return nil, fmt.Errorf("error decoding info - failed at offset %d (%s): %w", offset, "idb", err)
	}

	ad, offset, err := deserialize(input, offset, encodingLength)
	if err != nil {
		return nil, fmt.Errorf("error decoding info - failed at offset %d (%s): %w", offset, "ad", err)
	}

	dsi1, offset, err := deserialize(input, offset, encodingLength)
	if err != nil {
		return nil, fmt.Errorf("error decoding info - failed at offset %d (%s): %w", offset, "dsi1", err)
	}

	dsi2, offset, err := deserialize(input, offset, encodingLength)
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
