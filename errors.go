package cpace

import (
	"errors"
	"fmt"
)

const (
	errPrefixSetup    = "CPACE - SETUP"
	errPrefixInternal = "CPACE - INTERNAL FAILURE"
	errPrefixImplem   = "CPACE - INTERNAL - implementation error"
	errPrefixPeerData = "CPACE - PEER DATA"
)

func errorSetup(err string) error {
	return fmt.Errorf("%s : %w", errPrefixSetup, errors.New(err))
}

func errorInternal(err string) error {
	return fmt.Errorf("%s : %w", errPrefixInternal, errors.New(err))
}

func errorImplementation(err string) error {
	return fmt.Errorf("%s : %w", errPrefixImplem, errors.New(err))
}

func errorPeerData(err string) error {
	return fmt.Errorf("%s : %w", errPrefixPeerData, errors.New(err))
}

// Setup errors.
var (
	errSetupSIDTooShort = errorSetup(fmt.Sprintf("session id is too short (< %d)", minSidLength))
	errSetupLongID      = errorSetup("id exceeds authorised length")
	errSetupLongPeerID  = errorSetup("peer ID exceeds authorised length")
	errSetupLongAD      = errorSetup("AD exceeds authorised length")
)

// Responder specific errors.
var errRespNilMsg = errorImplementation("responder can't handle nil messages")

// Initiator specific errors.
var errInitReInit = errorImplementation("unexpected nil message - already initialised")

var (
	errInitSIDInvalid   = errorPeerData("session id received from peer is either nil or too short")
	errInitSIDDifferent = errorPeerData("session id from received from peer is different")
)

// Errors resulting from invalid peer data.
var (
	errPeerEncoding        = errorPeerData("decoding errored")
	errPeerElementNil      = errorPeerData("peer element is either nil or of size 0")
	errPeerElementInvalid  = errorPeerData("peer element yields error")
	errPeerElementIdentity = errorPeerData("invalid peer message : identity element")
)

// Other errors.
var (
	errInternalNoPublicPoint     = errorImplementation("public point not set - not initiated ?")
	errInternalUnexpectedMessage = errorImplementation("received message on unexpected stage")
)

// These are used in panics for internal inconsistencies, that should not occur.
var (
	errInternalInvalidRole = errorInternal("invalid role (should not happen)")
	errInternalNoSID       = errorInternal("session id is not set (should not happen)")
)
