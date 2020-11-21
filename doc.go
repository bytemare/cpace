// Package cpace provides an easy to use CPace PAKE implementation to do secure mutual authentication based on passwords.
//
// CPace implements the CFRG recommended balanced Password Authentication Key Exchange.
//
// !!! WARNING : THIS IMPLEMENTATION IS PROOF OF CONCEPT AND BASED ON THE LATEST INTERNET DRAFT.
// THERE ARE ABSOLUTELY NO WARRANTIES. !!!
//
// CPace allows two parties sharing a common secret or password to securely agree on a session key for secure communication.
// It's a dead simple protocol with only two messages, yet state of the art key exchange based on a shared secret.
// NB: The registration of the secret password is not in the scope of the protocol or this implementation.
//
package cpace
