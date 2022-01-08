# CPace
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/cpace.svg)](https://pkg.go.dev/github.com/bytemare/cpace)

CPace provides secure mutual authentication based on a pre-shared secret or password.

This package implements https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace.

**!!! WARNING: THIS IMPLEMENTATION IS PROOF OF CONCEPT AND BASED ON THE LATEST INTERNET-DRAFT.
THERE ARE ABSOLUTELY NO WARRANTIES. !!!**

CPace allows two parties sharing a common secret or password to securely agree on a session key for secure communication.
It's a dead-simple protocol with only two messages, yet a state of the art key exchange based on a shared secret.

Note: The registration of the secret password is not in the scope of the protocol or this implementation.

## Get it

    go get github.com/bytemare/cpace

## Use it

The API is minimal and very easy to use.

### Initialization

First, define the cryptographic parameters you want to use:

```Go
package cpace

import (
    "github.com/bytemare/cpace"
    "github.com/bytemare/crypto/group"
    "github.com/bytemare/crypto/hash"
)

params := &cpace.Parameters{
        Group: ciphersuite.Ristretto255Sha512,
        Hash:  hash.SHA512,
    }
```

Then initialize it with peer information. Note that you can then store this structure offline and (re)use it for the sessions between these peers.

```Go
params.Init(clientID, serverID, nil).New(Initiator)

// If needed
encoded := params.Serialize()
decoded, err := cpace.DeserializeParameters(encoded)
```

### Protocol execution

On protocol execution, derive a peer by specifying its role:

```Go
client := params.New(Initiator)

// or

server := params.New(Responder)
```

* `Start()` returns the peer's public share to be transmitted. If no sid is given to the initiator, this function generates a new sid and returns it. If no sid is given to the responder, it returns an error. The sid must be the same for both peers.
* `Finish()` takes the peer's public share and returns the session key.

If and only if the peers use the correct values they derive the same session key. If not, nothing about the password leaks.

<details>
<summary>Full Example:</summary>

```Go
package cpace

import (
    "github.com/bytemare/cpace"
    "github.com/bytemare/crypto/group"
    "github.com/bytemare/crypto/hash"
)

clientID := []byte("client")
serverID := []byte("server")
password := []byte("password")
var ad []byte = nil // this can securely be nil

// Set cryptographic parameters
params := &cpace.Parameters{
   Group: ciphersuite.Ristretto255Sha512,
   Hash:  hash.SHA512,
}

// Prepare common communication info
info := params.Init(clientID, serverID, ad)

// Get a client and a server
client := info.Initiator()
server := info.Responder()

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
```
</details>

## Under the hood

All cryptographic operations can be found in the [crypto package](https://github.com/bytemare/crypto), which itself uses either the standard library or tested and proved external libraries.

## Deploy it

Don't, yet.
