package cpace

import (
	"bytes"
	"fmt"

	"github.com/bytemare/cryptotools/encoding"
)

func ExampleCPace() {
	serverID := []byte("server")
	username := []byte("client")
	password := []byte("password")

	var ad []byte = nil

	clientParams := &Parameters{
		ID:       username,
		PeerID:   serverID,
		Secret:   password,
		SID:      nil,
		AD:       ad,
		Encoding: encoding.Gob,
	}

	// Set up the initiator, let's call it the client
	client, err := Client(clientParams, nil)
	if err != nil {
		panic(err)
	}

	// Start the protocol.
	// message1 must then be sent to the responder
	message1, err := client.Authenticate(nil)
	if err != nil {
		panic(err)
	}

	serverParams := &Parameters{
		ID:       serverID,
		PeerID:   username,
		Secret:   password,
		SID:      nil,
		AD:       ad,
		Encoding: encoding.Gob,
	}

	// Set up the responder, let's call it the server
	server, err := Server(serverParams, nil)
	if err != nil {
		panic(err)
	}

	// Handle the initiator's message, and send back message2. At this point the session key can already be derived.
	message2, err := server.Authenticate(message1)
	if err != nil {
		panic(err)
	}

	// Give the initiator the responder's answer. Since we're in implicit authentication, no message comes out here.
	// After this, the initiator can derive the session key.
	_, err = client.Authenticate(message2)
	if err != nil {
		panic(err)
	}

	// The protocol is finished, and both parties now share the same secret session key
	if bytes.Equal(client.SessionKey(), server.SessionKey()) {
		fmt.Println("Success ! Both parties share the same secret session key !")
	} else {
		fmt.Println("Failed. Client and server keys are different.")
	}
	// Output: Success ! Both parties share the same secret session key !
}
