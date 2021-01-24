package cpace

import (
	"bytes"
	"fmt"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
)

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
