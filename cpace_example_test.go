package cpace

import (
	"bytes"
	"fmt"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
)

var testResponder, testInitiator *CPace
var testResponderSK []byte

func receiveFromResponder(epkc, sid []byte) []byte {
	clientID := []byte("client")
	serverID := []byte("server")
	password := []byte("password")
	params := &Parameters{
		Group: ciphersuite.Ristretto255Sha512,
		Hash:  hash.SHA512,
	}
	testResponder = params.Init(clientID, serverID, nil).New(Responder)
	epks, _, err := testResponder.Start(password, sid)
	if err != nil {
		panic(err)
	}

	testResponderSK, err = testResponder.Finish(epkc)
	if err != nil {
		panic(err)
	}

	return epks
}

func receiveFromClient() (epku, sid []byte) {
	clientID := []byte("client")
	serverID := []byte("server")
	password := []byte("password")
	params := &Parameters{
		Group: ciphersuite.Ristretto255Sha512,
		Hash:  hash.SHA512,
	}
	testInitiator = params.Init(clientID, serverID, nil).New(Initiator)
	epku, sid, err := testInitiator.Start(password, nil)
	if err != nil {
		panic(err)
	}

	return epku, sid
}

func clientSecretKey(epks []byte) []byte {
	sk, err := testInitiator.Finish(epks)
	if err != nil {
		panic(err)
	}

	return sk
}

func ExampleInitiator() {
	clientID := []byte("client")
	serverID := []byte("server")
	password := []byte("password")
	var sid []byte = nil // if nil, sid will be set randomly in Start()
	var ad []byte = nil

	// Set cryptographic parameters
	params := &Parameters{
		Group: ciphersuite.Ristretto255Sha512,
		Hash:  hash.SHA512,
	}

	// Prepare common communication info, and directly derive the client
	client := params.Init(clientID, serverID, ad).New(Initiator)

	// Client starts. If no sid is given for the client, the function returns a new sid.
	epku, sid, err := client.Start(password, sid)
	if err != nil {
		panic(err)
	}

	// The client receives the server epks, and can derive the session key.
	epks := receiveFromResponder(epku, sid)

	clientSK, err := client.Finish(epks)
	if err != nil {
		panic(err)
	}

	// The client has not access to the server's result, but if everything went fine, the session keys are the same.
	if bytes.Equal(clientSK, testResponderSK) {
		fmt.Println("Success ! Both parties share the same secret session key !")
	} else {
		fmt.Println("Failed. Client and server keys are different.")
	}
	// Output: Success ! Both parties share the same secret session key !
}

func ExampleResponder() {
	clientID := []byte("client")
	serverID := []byte("server")
	password := []byte("password")
	var ad []byte = nil

	// Set cryptographic parameters
	params := &Parameters{
		Group: ciphersuite.Ristretto255Sha512,
		Hash:  hash.SHA512,
	}

	// Prepare common communication info, and directly derive the responder
	responder := params.Init(clientID, serverID, ad).New(Responder)

	// The responder either already knows the sid, or receives it from the initiator, along with epku
	epku, sid := receiveFromClient()

	// The responder computes its epks given the password and sid, and sends epks to the client
	epks, sid, err := responder.Start(password, sid)
	if err != nil {
		panic(err)
	}

	// The responder can now derive the session key.
	responderSK, err := responder.Finish(epku)
	if err != nil {
		panic(err)
	}

	// The responder has not access to the initiator's result, but if everything went fine, the session keys are the same.
	if bytes.Equal(responderSK, clientSecretKey(epks)) {
		fmt.Println("Success ! Both parties share the same secret session key !")
	} else {
		fmt.Println("Failed. Client and server keys are different.")
	}
	// Output: Success ! Both parties share the same secret session key !
}

func ExampleCPace() {
	clientID := []byte("client")
	serverID := []byte("server")
	password := []byte("password")
	var ad []byte = nil

	// Set cryptographic parameters
	params := &Parameters{
		Group: ciphersuite.Ristretto255Sha512,
		Hash:  hash.SHA512,
	}

	// Prepare common communication info
	info := params.Init(clientID, serverID, ad)

	// Get a client and a server
	client := info.New(Initiator)
	server := info.New(Responder)

	// Client starts. If no sid is given for the client, the function returns a new sid.
	epku, sid, err := client.Start(password, nil)
	if err != nil {
		panic(err)
	}

	// The server receives sends back its own epks.
	// The sid should be the same as from the client, and can even be the one the client sent.
	epks, _, err := server.Start(password, sid)
	if err != nil {
		panic(err)
	}

	// The session key can already be derived by the server using the client's epku.
	// If they differ, one of the peers used the wrong password.
	serverSK, err := server.Finish(epku)
	if err != nil {
		panic(err)
	}

	// The client receives the server epks, and can derive the session key.
	clientSK, err := client.Finish(epks)
	if err != nil {
		panic(err)
	}

	// The protocol is finished, and both parties now share the same secret session key
	if bytes.Equal(serverSK, clientSK) {
		fmt.Println("Success ! Both parties share the same secret session key !")
	} else {
		fmt.Println("Failed. Client and server keys are different.")
	}
	// Output: Success ! Both parties share the same secret session key !
}
