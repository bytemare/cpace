// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package cpace provides an easy to use CPace PAKE implementation to do secure mutual
// authentication based on a shared password.
//
// CPace implements the CFRG recommended balanced Password Authentication Key Exchange.
//
// !!! WARNING : THIS IMPLEMENTATION IS PROOF OF CONCEPT AND BASED ON THE LATEST INTERNET DRAFT.
// THERE ARE ABSOLUTELY NO WARRANTIES. !!!
//
// CPace allows two parties sharing a common secret or password to securely agree on a
// session key for secure communication.
// It's a dead simple protocol with only two messages, yet state of the art key exchange
// based on a shared secret.
// NB: The registration of the secret password is not in the scope of the protocol or this implementation.
package cpace
