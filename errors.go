package cpace

import (
	"errors"
	"fmt"
)

// Setup errors.
var (
	errSetupSIDNil      = errors.New("setup - session id is nil")
	errSetupSIDTooShort = fmt.Errorf("setup - session id is too short (< %d)", minSidLength)
)

// Errors resulting from invalid peer data.
var (
	errPeerElementNil      = errors.New("peer data - peer element is either nil or of size 0")
	errPeerElementInvalid  = errors.New("peer data - peer element decoding error")
	errPeerElementIdentity = errors.New("peer data - invalid peer message : identity element")
)

// Other errors.
var errNoEphemeralPubKey = errors.New("public point not set - not initiated? ")
