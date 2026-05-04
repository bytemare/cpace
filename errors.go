package cpace

import (
	"errors"
	"fmt"
)

// Setup errors.
var (
	errSetupSIDNil      = errors.New("setup - session id is nil")
	errSetupSIDTooShort = fmt.Errorf("setup - session id is too short (< %d)", minSidLength)

	errEncodingShort       = errors.New("parameter encoding is too short")
	errEncodingCiphersuite = errors.New("ciphersuite identifier not recognised or unavailable")
	errEncodingHash        = errors.New("hash identifier not recognised or unavailable")
	errDecodingBounds      = errors.New("array index out of bounds")
)

// Errors resulting from invalid peer data.
var (
	errPeerElementNil      = errors.New("peer data - peer element is either nil or of size 0")
	errPeerElementInvalid  = errors.New("peer data - peer element decoding error")
	errPeerElementIdentity = errors.New("peer data - invalid peer message : identity element")
)

// Other errors.
var errNoEphemeralPubKey = errors.New("public point not set - not initiated? ")

var (
	// ErrInputEmpty happens when the input is nil or empty.
	ErrInputEmpty = errors.New("nil or empty input")

	// ErrInputTooLarge happens when the input is longer than 4 bytes.
	ErrInputTooLarge = errors.New("input too large for integer")
)
