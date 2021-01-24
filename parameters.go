package cpace

import (
	"fmt"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
)

// Parameters identifies the components of a Ciphersuite.
type Parameters struct {
	Group ciphersuite.Identifier `json:"group"`
	Hash  hash.Identifier        `json:"hash"`
}

// Init returns a pointer to an Info structure, enabling pre-computation of the common initialization state between the peers.
func (p *Parameters) Init(ida, idb, ad []byte) *Info {
	return &Info{
		Parameters: *p,
		Ida:        ida,
		Idb:        idb,
		Ad:         ad,
		Dsi1:       []byte(fmt.Sprintf("%s%s-%d", cpace, p.Group, 1)),
		Dsi2:       []byte(fmt.Sprintf("%s%s-%d", cpace, p.Group, 2)),
	}
}

// Info holds the CPace initialization state. It can be pre-computed, stored, and reused.
type Info struct {
	// Parameters holds the cryptographic settings to be used.
	Parameters `json:"Parameters"`

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

// New returns a pointer to a CPace structure for the specified initiator or responder role.
func (i *Info) New(role Role) *CPace {
	h2gDST := []byte(cpace + i.Group.String())

	return &CPace{
		role:  role,
		group: i.Group.Get(h2gDST),
		info:  *i,
		state: state{},
	}
}
