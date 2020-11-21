// Package cpace provides an easy to use CPace implementation
package cpace

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/bytemare/cryptotools"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hashtogroup"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/pake"
	"github.com/bytemare/pake/message"
)

const (
	Protocol    = "CPace"
	Version     = "0.0.0"
	maxIDLength = 1<<16 - 1
)

var errInternalKexAssertion = errors.New("internal: something went wrong in type assertion to Kex message")

// Parameters groups a party's input parameters
type Parameters struct {
	// ID is own identity
	ID []byte

	// PeerID identifies the remote peer
	PeerID []byte

	// Secret is the shared secret, e.g. the password
	Secret []byte

	// SID is the session identifier, a unique random byte array of at least 16 bytes
	SID []byte

	// AD
	AD []byte

	// Encoding specifies which encoding should be used for outgoing and incoming messages
	Encoding encoding.Encoding
}

// CPace wraps the core CPace session and state info and enriches them with a more abstract API
type CPace struct {
	session
	state
}

func validateCI(id, peerID, ad []byte) error {
	switch {
	case len(id) > maxIDLength:
		return errSetupLongID
	case len(peerID) > maxIDLength:
		return errSetupLongPeerID
	case len(ad) > maxIDLength:
		return errSetupLongAD
	default:
		return nil
	}
}

func assembleCI(role pake.Role, id, peerID, ad []byte) ([]byte, error) {
	ci := make([]byte, 0, len(id)+len(peerID)+len(ad))
	b := cryptobyte.NewBuilder(ci)

	switch role {
	case pake.Initiator:
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(id) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(peerID) })
	case pake.Responder:
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(peerID) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(id) })
	default:
		return nil, fmt.Errorf("assembleCI : %w", errInternalInvalidRole)
	}

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(ad) })

	return b.BytesOrPanic(), nil
}

func buildDST(identifier hashtogroup.Ciphersuite, in int) []byte {
	return []byte(fmt.Sprintf("%s%s-%d", Protocol, identifier, in))
}

func newCPace(role pake.Role, parameters *Parameters, csp *cryptotools.Parameters) (*CPace, error) {
	if err := parameters.Encoding.Available(); err != nil {
		return nil, err
	}

	// Verify session id and generate one for the initiator if none provided
	switch l := len(parameters.SID); {
	case l == 0:
		// If none is given for the Responder, we'll take it from the initiator's first message
		if role == pake.Initiator {
			parameters.SID = utils.RandomBytes(minSidLength)
		}
	case l < minSidLength:
		return nil, errSetupSIDTooShort
	}

	if err := validateCI(parameters.ID, parameters.PeerID, parameters.AD); err != nil {
		return nil, err
	}

	ci, err := assembleCI(role, parameters.ID, parameters.PeerID, parameters.AD)
	if err != nil {
		return nil, err
	}

	// meta := pake.MetaData()

	pakeCore, err := pake.KeyExchange.New(Protocol, Version, parameters.Encoding, csp, role, parameters.PeerID)
	if err != nil {
		return nil, err
	}

	return &CPace{
		session: session{
			role: role,
			sid:  parameters.SID,
			cid:  ci,
		},
		state: state{
			password: parameters.Secret,
			core:     pakeCore,
			dsi1:     buildDST(pakeCore.Crypto.Parameters.Group, 1),
			dsi2:     buildDST(pakeCore.Crypto.Parameters.Group, 2),
		},
	}, nil
}

// Client returns a new CPace client instance
func Client(parameters *Parameters, csp *cryptotools.Parameters) (pake.Pake, error) {
	return newCPace(pake.Initiator, parameters, csp)
}

// Server returns a new CPace server instance
func Server(parameters *Parameters, csp *cryptotools.Parameters) (pake.Pake, error) {
	return newCPace(pake.Responder, parameters, csp)
}

// AuthenticateKex interprets the key exchange message and operates the consecutive steps of the protocol.
func (c *CPace) AuthenticateKex(m *message.Kex) (*message.Kex, error) {
	switch c.role {
	case pake.Initiator:
		if c.core.Expect != message.StageResponse {
			return nil, errInternalUnexpectedMessage
		}

		// We should only enter here when initialising the initiator, i.e. with a nil message
		if m == nil {
			// If own public element has already been set, it means we've already initiated the client
			if c.publicElement != nil {
				return nil, errInitReInit
			}

			// We want to start the protocol
			elem, sid, err := c.initiate()
			if err != nil {
				return nil, err
			}

			return &message.Kex{
				Element: elem,
				Auth:    sid,
			}, nil
		}

		return nil, c.finish(m.Element)

	case pake.Responder:
		if c.core.Expect != message.StageStart {
			return nil, errInternalUnexpectedMessage
		}

		if m == nil {
			return nil, errRespNilMsg
		}

		elem, err := c.response(m.Element, m.Auth)
		if err != nil {
			return nil, err
		}

		return &message.Kex{
			Element: elem,
			Auth:    nil,
		}, nil
	}

	return nil, errInternalInvalidRole
}

// Authenticate decodes the payload as a Kex message and operates the consecutive steps of the protocol.
func (c *CPace) Authenticate(m []byte) ([]byte, error) {
	kex, err := decodeKeyExchange(m, c.core.Encoding())
	if err != nil {
		return nil, errPeerEncoding // todo : should we wrap the error ?
	}

	r, err := c.AuthenticateKex(kex)
	if err != nil {
		return nil, err
	}

	// On success, the initiator returns nil
	if r == nil {
		return nil, nil
	}

	return r.Encode(c.core.Encoding())
}

// SessionKey returns the session's intermediary secret session key
func (c *CPace) SessionKey() []byte {
	return c.iSessionKey
}

// EncodedParameters returns the 4-byte encoding of the ciphersuite parameters
func (c *CPace) EncodedParameters() cryptotools.CiphersuiteEncoding {
	return c.core.Crypto.Parameters.Encode()
}

// decodeKeyExchange decodes messages in the simple Kex format, returns nil on nil message.
func decodeKeyExchange(m []byte, enc encoding.Encoding) (*message.Kex, error) {
	if m == nil {
		return nil, nil
	}

	k, err := enc.Decode(m, &message.Kex{})
	if err != nil {
		return nil, err
	}

	kex, ok := k.(*message.Kex)
	if !ok {
		return nil, errInternalKexAssertion
	}

	return kex, nil
}
