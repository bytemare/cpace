// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package cpace

import (
	"errors"
	"fmt"
)

// Setup errors.
var (
	ErrSetupSIDNil      = errors.New("setup - session id is nil")
	ErrSetupSIDTooShort = fmt.Errorf("setup - session id is too short (< %d)", MinSidLength)

	ErrEncodingShort       = errors.New("parameter encoding is too short")
	ErrEncodingCiphersuite = errors.New("ciphersuite identifier not recognised or unavailable")
	ErrEncodingHash        = errors.New("hash identifier not recognised or unavailable")
	errDecodingBounds      = errors.New("array index out of bounds")
)

// Errors resulting from invalid peer data.
var (
	ErrPeerElementNil      = errors.New("peer data - peer element is either nil or of size 0")
	ErrPeerElementInvalid  = errors.New("peer data - peer element decoding error")
	ErrPeerElementIdentity = errors.New("peer data - invalid peer message : identity element")
)

// Other errors.
var ErrNoEphemeralPubKey = errors.New("public point not set - not initiated? ")
