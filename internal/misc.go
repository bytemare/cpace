// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"encoding/binary"
	"errors"
)

var (
	// ErrInputEmpty happens when the input is nil or empty.
	ErrInputEmpty = errors.New("nil or empty input")

	// ErrInputTooLarge happens when the input is longer than 4 bytes.
	ErrInputTooLarge = errors.New("input too large for integer")
)

// OS2IP Octet Stream to Integer Primitive on maximum 4 bytes / 32 bits.
func OS2IP(input []byte) int {
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
