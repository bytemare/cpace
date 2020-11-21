# CPace

CPace provides an easy to use CPace PAKE implementation to do secure mutual authentication based on passwords.

CPace implements https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace.

**!!! WARNING : THIS IMPLEMENTATION IS PROOF OF CONCEPT AND BASED ON THE LATEST INTERNET DRAFT.
THERE ARE ABSOLUTELY NO WARRANTIES. !!!**

CPace allows two parties sharing a common secret or password to securely agree on a session key for secure communication.
It's a dead simple protocol with only two messages, yet state of the art key exchange based on a shared secret.

Note: The registration of the secret password is not in the scope of the protocol or this implementation.

# Get it

go get -u github.com/bytemare/cpace

# Use it

The API is really minimal and very easy to use.

- New() returns the structure through which the steps are made. It is the same struct type for the client and the server.
- Authenticate() takes a message and returns one. If this function returns a message, it should be sent to the peer.
- SessionKey() returns the fresh session key, if everything went fine.

Messages are of type message.Kex, from the companion pake package. These message have built-in methods for encoding and decoding to different formats like Gob and Json.

<details>
<summary>Example:</summary>

```Go
        serverID := []byte("server")
	username := []byte("client")
	password := []byte("password")

	var ad = []byte("myAuth")

	// Set up the initiator, let's call it the client
	client, err := New(pake.Initiator, username, serverID, password, nil, ad, nil)
	if err != nil { panic(err) }

	// Start the protocol.
	// message1 must then be sent to the responder
	message1, err := client.Authenticate(nil)
	if err != nil { panic(err) }

	// Set up the responder, let's call it the server
	server, err := New(pake.Responder, serverID, username, password, nil, ad, nil)
	if err != nil { panic(err) }

	// Handle the initiator's message, and send back message2. At this point the session key can already be derived.
	message2, err := server.Authenticate(message1)
	if err != nil { panic(err) }

	// Give the initiator the responder's answer. Since we're in implicit authentication, no message comes out here.
	// After this, the initiator can derive the session key.
	_, err = client.Authenticate(message2)
	if err != nil { panic(err) }
```
</details>

# Under the hood

All cryptographic operations can be found in the [cryptotools package](https://github.com/bytemare/cryptotools), which itself uses either the standard library or tested and proved external libraries.

# Deploy it

Don't, yet.

## Work on it

- Closely follow draft evolution
- More testing, with vectors, if available
- Fuzzing
