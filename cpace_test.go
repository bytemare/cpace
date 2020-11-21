package cpace

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/stretchr/testify/assert"

	"github.com/bytemare/cryptotools"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/pake"
	"github.com/bytemare/pake/message"
)

type testNew struct {
	*Parameters
	csp *cryptotools.Parameters
}

func newTestCPace(role pake.Role, params *Parameters, csp *cryptotools.Parameters, tb testing.TB) pake.Pake {
	var c pake.Pake
	var err error
	if role == pake.Initiator {
		c, err = Client(params, csp)
	} else {
		c, err = Server(params, csp)
	}
	if err != nil {
		tb.Fatal(err)
	}

	return c
}

func goodCPace(role pake.Role, tb testing.TB) pake.Pake {
	return newTestCPace(role, goodNew[role].Parameters, goodNew[role].csp, tb)
}

var goodNew = map[pake.Role]testNew{
	pake.Initiator: {&Parameters{[]byte("initiator"), []byte("responder"), []byte("secret"), nil, nil, encoding.Gob}, nil},
	pake.Responder: {&Parameters{[]byte("responder"), []byte("initiator"), []byte("secret"), nil, nil, encoding.Gob}, nil},
}

func TestUnexpectedMessages(t *testing.T) {
	i := goodCPace(pake.Initiator, t)
	r := goodCPace(pake.Responder, t)

	// Operate key exchange
	cpaceRun(i, r, t)

	// Test initiator
	_, err := i.Authenticate(nil)
	if !errors.Is(err, errInternalUnexpectedMessage) {
		t.Errorf("must return error on unexpected message. expected '%v', got '%v'", errInternalUnexpectedMessage, err)
	}

	// Test responder
	_, err = r.Authenticate(nil)
	if !errors.Is(err, errInternalUnexpectedMessage) {
		t.Errorf("must return error on unexpected message. expected '%v', got '%v'", errInternalUnexpectedMessage, err)
	}

	// Test when initiator receives a valid message without being initialised
	i = goodCPace(pake.Initiator, t)
	r = goodCPace(pake.Responder, t)

	m1, _ := i.Authenticate(nil)
	m2, _ := r.Authenticate(m1)
	i = goodCPace(pake.Initiator, t)

	_, err = i.Authenticate(m2)
	if !errors.Is(err, errInternalNoPublicPoint) {
		t.Errorf("expected error when calling Authenticate() on initiator without its initialisation."+
			"expected '%v', got '%v'", errInternalNoPublicPoint, err)
	}
}

func TestNilMessage(t *testing.T) {
	i := goodCPace(pake.Initiator, t)
	r := goodCPace(pake.Responder, t)

	// Make the initiator do a first step
	_, err := i.Authenticate(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Test initiator
	_, err = i.Authenticate(nil)
	if !errors.Is(err, errInitReInit) {
		t.Errorf("must return error on nil message. expected '%v', got '%v'", errRespNilMsg, err)
	}

	// Test responder
	_, err = r.Authenticate(nil)
	if !errors.Is(err, errRespNilMsg) {
		t.Errorf("must return error on nil message. expected '%v', got '%v'", errRespNilMsg, err)
	}
}

//func TestInvalidRole(t *testing.T) {
//	invalidRole := pake.Role(3)
//
//	// Should error on New, during ci assembling
//	p := &Parameters{invalidRole, goodNew[pake.Initiator].Identifier, goodNew[pake.Initiator].PeerID,
//		goodNew[pake.Initiator].Secret, goodNew[pake.Initiator].SID, goodNew[pake.Initiator].AD, goodNew[pake.Initiator].Encoding}
//
//	_, err := New(p, nil)
//	if !errors.Is(err, errInternalInvalidRole) {
//		t.Errorf("expected error in New(). expected '%v', got '%v'", errInternalInvalidRole, err)
//	}
//
//	i := goodCPace(pake.Initiator, t)
//
//	i.cpace.role = invalidRole
//
//	//assert.PanicsWithError(t, errInternalInvalidRole.Error(), func() {
//	//	_ = i.transcript(nil)
//	//}, "expected panic in Authenticate()")
//
//	if _, err := i.Authenticate(nil); !errors.Is(err, errInternalInvalidRole) {
//		t.Fatalf("expected error on invalid role. Got %q", err)
//	}
//}

func TestNewNilSid(t *testing.T) {
	// Verify a sid is set internally for the initiator when none provided
	i := goodCPace(pake.Initiator, t).(*CPace)

	switch s := len(i.sid); {
	case s == 0:
		t.Fatal("session id has not been set, but should have")
	case s < minSidLength:
		t.Fatalf("patched session id is too short. Expected %d bytes, got %d )", s, minSidLength)
	}
}

func TestNewInvalidCiphersuite(t *testing.T) {
	csp := &cryptotools.Parameters{
		Group:  64,
		Hash:   64,
		IHF:    64,
		IHFLen: 64,
	}

	if _, err := Client(goodNew[pake.Initiator].Parameters, csp); err == nil {
		t.Fatalf("expected error on invalid CSP")
	}
}

func TestAuthenticateNilSid(t *testing.T) {
	r := goodCPace(pake.Responder, t).(*CPace)
	r.sid = nil

	// Responder receives a message without an sid, and none set
	kex := message.Kex{
		Element: nil,
		Auth:    nil,
	}

	m, err := kex.Encode(r.core.Encoding())
	if err != nil {
		t.Fatal(err)
	}

	_, err = r.Authenticate(m)
	if !errors.Is(err, errInitSIDInvalid) {
		t.Fatal("expect error on message with no sid and no sid set")
	}
}

func TestNilSid(t *testing.T) {
	i := goodCPace(pake.Initiator, t).(*CPace)
	i.sid = nil

	// Test initiator
	if _, err := i.Authenticate(nil); !errors.Is(err, errInternalNoSID) {
		t.Fatalf("expected error when calling Authenticate on nil message with no sid set. Got %q", err)
	}
}

func TestBadSid(t *testing.T) {
	// Initiator : Give it a short session id, should fail
	badSid := utils.RandomBytes(minSidLength - 1)

	p := &Parameters{
		SID:      badSid,
		Encoding: encoding.Gob,
	}

	_, err := Client(p, nil)
	//if c != nil {
	//	// todo : this is interesting, since c is nil but still passes the nil test
	//	t.Fatalf("invalid sid but still initialised a struct: %v\n%v\n", c, err)
	//}

	if !errors.Is(err, errSetupSIDTooShort) {
		t.Fatal("invalid error returned for small session identifier")
	}

	// Responder : check own and peer sid on message receiving
	r := goodCPace(pake.Responder, t).(*CPace)
	r.sid = nil

	// Responder receives a message with a short sid, and none set
	kex := message.Kex{
		Element: nil,
		Auth:    badSid,
	}

	m, err := kex.Encode(r.core.Encoding())
	if err != nil {
		t.Fatal(err)
	}

	_, err = r.Authenticate(m)
	if !errors.Is(err, errInitSIDInvalid) {
		t.Fatal("expect error on message with short sid and no sid set")
	}

	// The session id received by the responder from the initiator
	// is valid but different than the one set by the responder
	r.sid = utils.RandomBytes(minSidLength)
	kex.Auth = utils.RandomBytes(minSidLength)

	assert.NotEqual(t, r.sid, kex.Auth, "two random []byte are supposed to be different")

	m, err = kex.Encode(r.core.Encoding())
	if err != nil {
		t.Fatal(err)
	}

	_, err = r.Authenticate(m)
	if !errors.Is(err, errInitSIDDifferent) {
		t.Fatal("expect error on message with different sid when sid is set")
	}
}

func TestSkipInit(t *testing.T) {
	// Initiator should not derive the session key without its own public share
	i := goodCPace(pake.Initiator, t).(*CPace)
	kex := message.Kex{
		Element: utils.RandomBytes(32),
		Auth:    nil,
	}

	m, err := kex.Encode(i.core.Encoding())
	if err != nil {
		t.Fatal(err)
	}

	_, err = i.Authenticate(m)
	if !errors.Is(err, errInternalNoPublicPoint) {
		t.Fatal("expected error when initiator receives message when not having set its own public element")
	}
}

func TestDecodeKeyExchange(t *testing.T) {
	encodings := []encoding.Encoding{encoding.JSON, encoding.Gob}
	var kex = message.Kex{
		Element: utils.RandomBytes(32),
		Auth:    utils.RandomBytes(32),
	}

	for _, enc := range encodings {
		t.Run(string(enc), func(t *testing.T) {
			// Encode
			e, err := kex.Encode(enc)
			if err != nil {
				t.Fatalf("unexpected error: %q", err)
			}

			// Decode
			d, err := decodeKeyExchange(e, enc)
			if err != nil {
				t.Fatalf("unexpected error: %q", err)
			}

			// Check values
			assert.EqualValues(t, &kex, d)
		})
	}
}

func TestInvalidMessage(t *testing.T) {
	// Should fail when the received peer element is not a valid point
	init := goodCPace(pake.Initiator, t).(*CPace)
	resp := goodCPace(pake.Responder, t).(*CPace)

	m, err := init.Authenticate(nil)
	if err != nil {
		t.Fatal(err)
	}

	kex, err := decodeKeyExchange(m, init.core.Encoding())
	if err != nil {
		t.Fatal(err)
	}

	test := []struct {
		*message.Kex
		expectedError error
	}{
		{
			Kex: &message.Kex{
				Element: nil, // An element must not be nil
				Auth:    kex.Auth,
			},
			expectedError: errPeerElementNil,
		},
		{
			Kex: &message.Kex{
				Element: utils.RandomBytes(31), // Too short, supposed to be 32 bytes long
				Auth:    kex.Auth,
			},
			expectedError: errPeerElementInvalid,
		},
	}

	for i, msg := range test {
		msgEncoded, err := msg.Kex.Encode(resp.core.Encoding())
		if err != nil {
			t.Fatal(err)
		}

		// Responder
		_, err = resp.Authenticate(msgEncoded)
		if !errors.Is(err, msg.expectedError) {
			e := errors.Unwrap(err)
			t.Logf("unwrap to %v", e)

			t.Fatalf("%d : expect error when peer public element is not a valid point : %v", i, err)
		}

		if resp.SessionKey() != nil {
			t.Fatalf("%d : must not derive session key on invalid point", i)
		}

		// Initiator
		_, err = init.Authenticate(msgEncoded)
		if !errors.Is(err, msg.expectedError) {
			t.Fatalf("%d : expect error when peer public element is not a valid point", i)
		}

		if init.SessionKey() != nil {
			t.Fatalf("%d : must not derive session key on invalid point", i)
		}
	}

	// Should trigger decoding error
	m, err = test[0].Kex.Encode(resp.core.Encoding())
	if err != nil {
		t.Fatal(err)
	}

	m[0] ^= 0xff
	m[1] ^= 0xff
	m[2] ^= 0xff

	_, err = init.Authenticate(m)
	if !errors.Is(err, errPeerEncoding) {
		t.Fatalf("expected encoding error %q, got %q", errPeerEncoding, err)
	}
}

func TestNeutralElement(t *testing.T) {
	i := goodCPace(pake.Initiator, t).(*CPace)
	r := goodCPace(pake.Responder, t).(*CPace)

	badMessage := message.Kex{
		Element: ristretto255.NewElement().Zero().Encode(nil),
		Auth:    utils.RandomBytes(minSidLength),
	}

	m, err := badMessage.Encode(i.core.Encoding())
	if err != nil {
		t.Fatal(err)
	}

	// Responder should fail
	_, err = r.Authenticate(m)
	if !errors.Is(err, errPeerElementIdentity) {
		t.Fatal("expect error when initiator public element is not a valid point")
	}

	// Initiator should fail
	_, err = i.Authenticate(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = i.Authenticate(m)
	if !errors.Is(err, errPeerElementIdentity) {
		t.Fatal("expect error when responder public element is not a valid point")
	}
}

func TestCIOverflow(t *testing.T) {
	test := []struct {
		name, id, peerID, ad string
		expectedErr          error
	}{
		{
			name: "Long Identifier",
			id:   strings.Repeat("a", 1<<16), peerID: "b", ad: "ad",
			expectedErr: errSetupLongID,
		},
		{
			name: "Long peer Identifier",
			id:   "a", peerID: strings.Repeat("b", 1<<16), ad: "ad",
			expectedErr: errSetupLongPeerID,
		},
		{
			name: "Long AD",
			id:   "a", peerID: "b", ad: strings.Repeat("d", 1<<16),
			expectedErr: errSetupLongAD,
		},
	}

	for _, tt := range test {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			p := &Parameters{
				// Role:     64,
				ID:       []byte(tt.id),
				PeerID:   []byte(tt.peerID),
				Secret:   nil,
				SID:      nil,
				AD:       []byte(tt.ad),
				Encoding: encoding.Gob,
			}

			_, err := Client(p, nil)
			if !errors.Is(err, tt.expectedErr) {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}

func cpaceRun(init, responder pake.Pake, tb testing.TB) {
	message1, err := init.Authenticate(nil)
	if err != nil {
		tb.Fatalf("unexpected error : %v", err)
	}

	message2, err := responder.Authenticate(message1)
	if err != nil {
		tb.Fatalf("unexpected error : %v", err)
	}

	_, err = init.Authenticate(message2)
	if err != nil {
		tb.Fatalf("unexpected error : %v", err)
	}
}

func fullTest(name string, init, responder *CPace, success bool, tb testing.TB) {
	// Operate key exchange
	cpaceRun(init, responder, tb)

	// Verify results
	keyA := init.SessionKey()
	keyB := responder.SessionKey()

	if success {
		if len(keyA) != 64 {
			tb.Errorf("%s : initiator key is of invalid length. Expected %d bytes, got %d", name, 64, len(keyA))
		}

		if len(keyB) != 64 {
			tb.Errorf("%s : responder key is of invalid length. Expected %d bytes, got %d", name, 64, len(keyA))
		}
	}

	if bytes.Equal(keyA, keyB) != success {
		tb.Errorf("%s : unexpected key equality. Expected %v, got %v\n%v\n%v\n", name, success, !success, keyA, keyB)
	}
}

func TestWrongIdentities(t *testing.T) {
	test := []struct {
		Name         string
		IDa, PeerIDa string
		IDb, PeerIDb string
		password     string
	}{
		{
			Name: "Wrong Identifier A",
			IDa:  "a", PeerIDa: "abc",
			IDb: "b", PeerIDb: "bcd",
			password: "secret",
		},
		{
			Name: "Wrong Identifier B",
			IDa:  "a", PeerIDa: "abc",
			IDb: "b", PeerIDb: "bcd",
			password: "secret",
		},
		{
			Name: "Mirrored IDs",
			IDa:  "a", PeerIDa: "b",
			IDb: "a", PeerIDb: "b",
			password: "secret",
		},
		{
			Name: "Concatenated IDs",
			IDa:  "ax", PeerIDa: "b",
			IDb: "xb", PeerIDb: "a",
			password: "secret",
		},
	}

	for _, tt := range test {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			ip := &Parameters{[]byte(tt.IDa), []byte(tt.PeerIDa), []byte(tt.password), nil, nil, encoding.Gob}
			rp := &Parameters{[]byte(tt.IDb), []byte(tt.PeerIDb), []byte(tt.password), nil, nil, encoding.Gob}

			i := newTestCPace(pake.Initiator, ip, nil, t).(*CPace)
			r := newTestCPace(pake.Responder, rp, nil, t).(*CPace)

			fullTest(tt.Name, i, r, false, t)
		})
	}
}

func TestResults(t *testing.T) {
	tests := []struct {
		Name                 string
		IDa, IDb             string
		PasswordA, PasswordB string
		AdA, AdB             string
		Success              bool
	}{
		{
			Name: "Valid, no ad, no sid",
			IDa:  "a", IDb: "b",
			PasswordA: "secret", PasswordB: "secret",
			AdA: "", AdB: "",
			Success: true,
		},
		{
			Name: "Valid, with ad, no sid",
			IDa:  "a", IDb: "b",
			PasswordA: "secret", PasswordB: "secret",
			AdA: "ad", AdB: "ad",
			Success: true,
		},
		{
			Name: "Valid, same identities",
			IDa:  "a", IDb: "a",
			PasswordA: "secret", PasswordB: "secret",
			AdA: "", AdB: "",
			Success: true,
		},
		{
			Name: "Invalid, different passwords",
			IDa:  "a", IDb: "b",
			PasswordA: "secret", PasswordB: "password",
			AdA: "", AdB: "",
			Success: false,
		},
		{
			Name: "Invalid, different ad",
			IDa:  "a", IDb: "b",
			PasswordA: "secret", PasswordB: "password",
			AdA: "ad", AdB: "da",
			Success: false,
		},
		{
			Name: "Invalid, missing ad",
			IDa:  "a", IDb: "b",
			PasswordA: "secret", PasswordB: "password",
			AdA: "", AdB: "adb",
			Success: false,
		},
		{
			Name: "Invalid, missing password",
			IDa:  "a", IDb: "b",
			PasswordA: "secret", PasswordB: "",
			AdA: "", AdB: "",
			Success: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			ip := &Parameters{[]byte(tt.IDa), []byte(tt.IDb), []byte(tt.PasswordA), nil, []byte(tt.AdA), encoding.Gob}
			rp := &Parameters{[]byte(tt.IDb), []byte(tt.IDa), []byte(tt.PasswordB), nil, []byte(tt.AdB), encoding.Gob}

			i := newTestCPace(pake.Initiator, ip, nil, t).(*CPace)
			r := newTestCPace(pake.Responder, rp, nil, t).(*CPace)

			fullTest(tt.Name, i, r, tt.Success, t)
		})
	}
}

func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		goodCPace(pake.Initiator, b)
	}
}

func BenchmarkAuthenticate_Responder(b *testing.B) {
	i := goodCPace(pake.Initiator, b)
	m1, _ := i.Authenticate(nil)

	for i := 0; i < b.N; i++ {
		r := goodCPace(pake.Responder, b)
		m2, err := r.Authenticate(m1)

		if m2 == nil || err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkAuthenticate_Full(b *testing.B) {
	for i := 0; i < b.N; i++ {
		init := goodCPace(pake.Initiator, b).(*CPace)
		resp := goodCPace(pake.Responder, b).(*CPace)

		fullTest("BenchmarkAuthenticate_Full", init, resp, true, b)
	}
}
