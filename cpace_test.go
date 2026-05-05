package cpace

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/hash"
)

const (
	testIDInit      = "initiator"
	testIDResponder = "responder"
	testAD          = "ad"
	testPassword    = "password"

	testErrNilResponderSidFmt    = "expected error on nil sid for responder. Got %q, want %q"
	testErrInvalidPeerElementFmt = "expected error on invalid peerElement. Got %q, want %q"
)

/*
	Functional Tests and Coverage
*/

func defaultParameters() *Parameters {
	return &Parameters{
		Group: ecc.Ristretto255Sha512,
		Hash:  hash.SHAKE128,
	}
}

func defaultInitialised() *Parameters {
	return defaultParameters().Init([]byte(testIDInit), []byte(testIDResponder), []byte(testAD))
}

func genTestParams() []*Parameters {
	testGroups := []ecc.Group{ecc.Ristretto255Sha512, ecc.P256Sha256}
	testHash := []hash.Hash{hash.SHA256, hash.SHAKE128}

	l := len(testGroups) * len(testHash)
	p := make([]*Parameters, l)

	i := 0
	for _, g := range testGroups {
		for _, h := range testHash {
			p[i] = &Parameters{
				Group: g,
				Hash:  h,
			}
			i++
		}
	}

	return p
}

func runCPace(initiator, responder *CPace, iPwd, rPwd, iSid, rSid []byte) ([]byte, error) {
	epku, sid, err := initiator.Start(iPwd, iSid)
	if err != nil {
		return nil, err
	}

	if rSid != nil {
		sid = rSid
	}

	epks, _, err := responder.Start(rPwd, sid)
	if err != nil {
		return nil, err
	}

	serverSK, err := responder.Finish(epku)
	if err != nil {
		return nil, err
	}

	clientSK, err := initiator.Finish(epks)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(serverSK, clientSK) {
		return nil, errors.New("client and server keys are different")
	}

	return clientSK, nil
}

func TestCPaceDefault(t *testing.T) {
	params := genTestParams()

	for i, p := range params {
		t.Run(fmt.Sprintf("%d: %s-%s", i, p.Group, p.Hash), func(t *testing.T) {
			info := p.Init([]byte(testIDInit), []byte(testIDResponder), []byte(testAD))
			client := info.new(Initiator)
			server := info.new(Responder)

			_, err := runCPace(client, server, []byte(testPassword), []byte(testPassword), nil, nil)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
		})
	}
}

func TestCPaceResponderNilSid(t *testing.T) {
	i := defaultInitialised()
	s := i.new(Responder)
	if _, _, err := s.Start([]byte(testPassword), nil); err == nil || err.Error() != errSetupSIDNil.Error() {
		t.Fatalf(testErrNilResponderSidFmt, err, errSetupSIDNil)
	}
}

func TestCPaceShortSid(t *testing.T) {
	i := defaultInitialised()
	sid := []byte("short sid")
	client := i.new(Initiator)
	server := i.new(Responder)
	if _, _, err := client.Start([]byte(testPassword), sid); err == nil || err.Error() != errSetupSIDTooShort.Error() {
		t.Fatalf(testErrNilResponderSidFmt, err, errSetupSIDTooShort)
	}
	if _, _, err := server.Start([]byte(testPassword), sid); err == nil || err.Error() != errSetupSIDTooShort.Error() {
		t.Fatalf(testErrNilResponderSidFmt, err, errSetupSIDTooShort)
	}
}

func TestCPaceWrongSid(t *testing.T) {
	i := defaultInitialised()
	initiator := i.new(Initiator)
	responder := i.new(Responder)

	var csid, ssid [minSidLength]byte
	_, _ = rand.Read(csid[:]) //nolint:errcheck // Documented to never return an error.
	_, _ = rand.Read(ssid[:]) //nolint:errcheck // Documented to never return an error.

	epku, _, err := initiator.Start([]byte(testPassword), csid[:])
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	epks, _, err := responder.Start([]byte(testPassword), ssid[:])
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	serverSK, err := responder.Finish(epku)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	clientSK, err := initiator.Finish(epks)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if bytes.Equal(serverSK, clientSK) {
		t.Fatal("Client and server keys are supposed to be different (different sid)")
	}
}

func TestCPaceEmptyShare(t *testing.T) {
	i := defaultInitialised()
	client := i.new(Initiator)
	server := i.new(Responder)

	if _, err := client.Finish(nil); err == nil || err.Error() != errNoEphemeralPubKey.Error() {
		t.Fatalf("expected error on empty own public key. Got %q, want %q", err, errNoEphemeralPubKey)
	}
	if _, err := server.Finish(nil); err == nil || err.Error() != errNoEphemeralPubKey.Error() {
		t.Fatalf("expected error on empty own public key. Got %q, want %q", err, errNoEphemeralPubKey)
	}
}

func TestCPacePeerElement(t *testing.T) {
	i := defaultInitialised()
	client := i.new(Initiator)
	server := i.new(Responder)
	emptyPeerElement := []byte("")

	_, sid, err := client.Start([]byte(testPassword), nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	_, _, err = server.Start([]byte(testPassword), sid)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	want := errPeerElementNil.Error()
	if _, err = client.Finish(nil); err == nil || err.Error() != want {
		t.Fatalf("expected error on nil peerElement. Got %q, want %q", err, want)
	}
	if _, err = server.Finish(nil); err == nil || err.Error() != want {
		t.Fatalf("expected error on nil peerElement. Got %q, want %q", err, want)
	}
	if _, err = client.Finish(emptyPeerElement); err == nil || err.Error() != want {
		t.Fatalf("expected error on empty peerElement. Got %q, want %q", err, want)
	}
	if _, err = server.Finish(emptyPeerElement); err == nil || err.Error() != want {
		t.Fatalf("expected error on empty peerElement. Got %q, want %q", err, want)
	}

	want = errPeerElementInvalid.Error()
	invalidPeerElement := []byte("invalid")
	if _, err = client.Finish(invalidPeerElement); err == nil || err.Error() != want {
		t.Fatalf(testErrInvalidPeerElementFmt, err, want)
	}
	if _, err = server.Finish(invalidPeerElement); err == nil || err.Error() != want {
		t.Fatalf(testErrInvalidPeerElementFmt, err, want)
	}

	identity := i.Group.NewElement().Encode()
	if _, err = client.Finish(identity); err == nil || !errors.Is(err, errPeerElementInvalid) {
		t.Fatalf(testErrInvalidPeerElementFmt, err, errPeerElementInvalid)
	}
	if _, err = server.Finish(identity); err == nil || !errors.Is(err, errPeerElementInvalid) {
		t.Fatalf(testErrInvalidPeerElementFmt, err, errPeerElementInvalid)
	}
}

func compareInfo(expected, actual *Info) error {
	if expected == nil {
		if actual != nil {
			return fmt.Errorf("expected nil info, got non-nil")
		}

		return nil
	}

	if actual == nil {
		return fmt.Errorf("expected non-nil info, got nil")
	}

	if !bytes.Equal(expected.Ida, actual.Ida) {
		return fmt.Errorf("expected ida=%q, got ida=%q", expected.Ida, actual.Ida)
	}

	if !bytes.Equal(expected.Idb, actual.Idb) {
		return fmt.Errorf("expected idb=%q, got idb=%q", expected.Idb, actual.Idb)
	}

	if !bytes.Equal(expected.Ad, actual.Ad) {
		return fmt.Errorf("expected ad=%q, got ad=%q", expected.Ad, actual.Ad)
	}

	if !bytes.Equal(expected.Dsi1, actual.Dsi1) {
		return fmt.Errorf("expected dsi=%q, got dsi=%q", expected.Dsi1, actual.Dsi1)
	}

	if !bytes.Equal(expected.Dsi2, actual.Dsi2) {
		return fmt.Errorf("expected dsi=%q, got dsi=%q", expected.Dsi2, actual.Dsi2)
	}

	return nil
}

func assertEqualParameters(t *testing.T, expected, actual *Parameters) {
	if expected.Group != actual.Group {
		t.Fatalf("Group mismatch. Expected %s, got %s", expected.Group, actual.Group)
	}

	if expected.Hash != actual.Hash {
		t.Fatalf("Hash mismatch. Expected %s, got %s", expected.Hash, actual.Hash)
	}

	if err := compareInfo(expected.Info, actual.Info); err != nil {
		t.Fatal(err)
	}
}

func TestParameterSerialization(t *testing.T) {
	p := defaultParameters()
	encodedP := p.Serialize()
	decodedP, err := DeserializeParameters(encodedP)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	assertEqualParameters(t, p, decodedP)

	p = defaultInitialised()
	encodedP = p.Serialize()
	decodedP, err = DeserializeParameters(encodedP)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	assertEqualParameters(t, p, decodedP)
}

func TestParameterDeserializationErrors(t *testing.T) {
	// Nil parameter
	var input []byte
	if _, err := DeserializeParameters(input); err == nil || !errors.Is(err, errEncodingShort) {
		t.Fatalf("expected error on short serialization, want %v got %v", errEncodingShort, err)
	}

	// Short
	input = []byte{1}
	if _, err := DeserializeParameters(input); err == nil || !errors.Is(err, errEncodingShort) {
		t.Fatalf("expected error on short serialization, want %v got %v", errEncodingShort, err)
	}

	// Non-existent group
	input = []byte{0, 0}
	if _, err := DeserializeParameters(input); err == nil || !errors.Is(err, errEncodingCiphersuite) {
		t.Fatalf("expected error on short serialization, want %v got %v", errEncodingCiphersuite, err)
	}

	// Non-existent hash function
	input = []byte{1, 0}
	if _, err := DeserializeParameters(input); err == nil || !errors.Is(err, errEncodingHash) {
		t.Fatalf("expected error on short serialization, want %v got %v", errEncodingHash, err)
	}

	// Corrupt Info length
	p := defaultInitialised()
	enc := p.Serialize()
	short := make([]byte, 5)
	copy(short, enc[:5])

	if _, err := DeserializeParameters(short); err == nil {
		t.Fatal("expected error on short serialization")
	}
}

func TestInfoSerialization(t *testing.T) {
	i, err := DeserializeInfo(nil)
	if i != nil {
		t.Fatalf("expected nil info, got %#v", i)
	}

	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	i = defaultInitialised().Info

	encoded := i.Serialize()
	decoded, err := DeserializeInfo(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if err = compareInfo(i, decoded); err != nil {
		t.Fatal(err)
	}
}

func TestInfoDeserializationErrors(t *testing.T) {
	i := defaultInitialised().Info
	encoded := i.Serialize()

	offset := 0
	offset = testInfoFieldDeserializationError(t, encoded, offset) // Ida
	offset = testInfoFieldDeserializationError(t, encoded, offset) // Idb
	offset = testInfoFieldDeserializationError(t, encoded, offset) // Ad
	offset = testInfoFieldDeserializationError(t, encoded, offset) // Dsi1
	offset = testInfoFieldDeserializationError(t, encoded, offset) // Dsi2

	_, err := DeserializeInfo(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func testInfoFieldDeserializationError(t *testing.T, fullInfo []byte, fieldOffset int) int {
	headerOffset := fieldOffset + encodingLength

	// Missing field (length but no payload)
	sub := make([]byte, encodingLength)
	copy(sub, fullInfo[fieldOffset:headerOffset])
	if _, err := DeserializeInfo(sub); err == nil {
		t.Fatal("expected error on short serialization")
	}

	// Corrupt field (length but short payload)
	l := os2ip(fullInfo[fieldOffset:headerOffset])
	subLen := headerOffset + l - 1
	sub = make([]byte, subLen) // shorten
	copy(sub, fullInfo[0:subLen])
	if _, err := DeserializeInfo(sub); err == nil {
		t.Fatal("expected error on corrupt field")
	}

	// Return the offset
	return fieldOffset + encodingLength + l
}

func TestCPace(t *testing.T) {
	p := defaultParameters()

	tests := []struct {
		Name                 string
		IDa, IDb             string
		PasswordA, PasswordB string
		AdA, AdB             string
		Success              bool
	}{
		{
			Name: "Valid, no ad",
			IDa:  "a", IDb: "b",
			PasswordA: "secret", PasswordB: "secret",
			AdA: "", AdB: "",
			Success: true,
		},
		{
			Name: "Valid, with ad",
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
		t.Run(tt.Name, func(t *testing.T) {
			c := p.Init([]byte(tt.IDa), []byte(tt.IDb), []byte(tt.AdA)).new(Initiator)
			s := p.Init([]byte(tt.IDa), []byte(tt.IDb), []byte(tt.AdB)).new(Responder)

			_, err := runCPace(c, s, []byte(tt.PasswordA), []byte(tt.PasswordB), nil, nil)
			if (err == nil) != tt.Success {
				t.Errorf("Unexpected result. Expected success %v, err %q", tt.Success, err)
			}
		})
	}
}

/*
	Benchmarks
*/

func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = defaultInitialised().new(Initiator)
	}
}

func BenchmarkStart(b *testing.B) {
	c := defaultInitialised().new(Initiator)

	for i := 0; i < b.N; i++ {
		if _, _, err := c.Start([]byte(testPassword), nil); err != nil {
			b.Fatalf("unexpected error: %s", err)
		}
	}
}

func BenchmarkFinish(b *testing.B) {
	c := defaultInitialised().new(Initiator)
	s := defaultInitialised().new(Responder)
	epkc, sid, err := c.Start([]byte(testPassword), nil)
	if err != nil {
		b.Fatalf("unexpected error: %s", err)
	}

	_, _, err = s.Start([]byte(testPassword), sid)
	if err != nil {
		b.Fatalf("unexpected error: %s", err)
	}

	for i := 0; i < b.N; i++ {
		_, err := s.Finish(epkc)
		if err != nil {
			b.Fatalf("unexpected error: %s", err)
		}
	}
}

func BenchmarkFull(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := defaultInitialised().new(Initiator)
		s := defaultInitialised().new(Responder)
		_, err := runCPace(c, s, []byte(testPassword), []byte(testPassword), nil, nil)
		if err != nil {
			b.Fatalf("unexpected error: %s", err)
		}
	}
}

/*
	Generate test vectors
*/

type ByteToHex []byte

func (j ByteToHex) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(j))
}

func (j *ByteToHex) UnmarshalJSON(b []byte) error {
	bs := strings.Trim(string(b), "\"")

	dst, err := hex.DecodeString(bs)
	if err != nil {
		return err
	}

	*j = dst
	return nil
}

type testVector struct {
	parameters `json:"Parameters"`
	input      `json:"Input"`
	output     `json:"Output"`
}

type parameters struct {
	GroupName string    `json:"HashToGroup"`
	SuiteID   ecc.Group `json:"SuiteID"`
	Hash      string    `json:"Hash"`
}

type input struct {
	Ida             ByteToHex `json:"Ida"`
	Idb             ByteToHex `json:"Idb"`
	Ad              ByteToHex `json:"AD"`
	Sid             ByteToHex `json:"SID"`
	Password        ByteToHex `json:"Password"`
	InitiatorScalar ByteToHex `json:"scalarA"`
	ResponderScalar ByteToHex `json:"scalarB"`
}

type output struct {
	DSI1       ByteToHex `json:"DSI1"`
	DSI2       ByteToHex `json:"DSI2"`
	H2GDst     ByteToHex `json:"HashToGroupDST"`
	Epku       ByteToHex `json:"Epku"`
	Epks       ByteToHex `json:"Epks"`
	SessionKey ByteToHex `json:"SessionKey"`
}

func generateTestVector(t *testing.T, params *Parameters) testVector {
	p := parameters{
		GroupName: params.Group.String(),
		SuiteID:   params.Group,
		Hash:      params.Hash.String(),
	}

	info := params.Init([]byte(testIDInit),
		[]byte(testIDResponder),
		[]byte(testAD))
	i := info.new(Initiator)
	r := info.new(Responder)
	pwd := []byte(testPassword)
	var sid [minSidLength]byte
	_, _ = rand.Read(sid[:])
	sk, err := runCPace(i, r, pwd, pwd, sid[:], sid[:])
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	in := input{
		Ida:             ByteToHex(testIDInit),
		Idb:             ByteToHex(testIDResponder),
		Ad:              ByteToHex(testAD),
		Sid:             sid[:],
		Password:        pwd,
		InitiatorScalar: i.Scalar(),
		ResponderScalar: r.Scalar(),
	}

	out := output{
		DSI1:       info.Dsi1,
		DSI2:       info.Dsi2,
		H2GDst:     []byte(cpace + i.group.String()),
		Epku:       i.epk,
		Epks:       r.epk,
		SessionKey: sk,
	}

	return testVector{
		parameters: p,
		input:      in,
		output:     out,
	}
}

func generateAllVectors(t *testing.T) []testVector {
	params := genTestParams()
	vectors := make([]testVector, len(params))

	for i, p := range params {
		vectors[i] = generateTestVector(t, p)
	}

	return vectors
}

func TestGenerateVectorFile(t *testing.T) {
	dir := "./tests"
	file := "allVectors.json"
	write := true

	vectors := generateAllVectors(t)
	content, _ := json.MarshalIndent(vectors, "", "  ")

	if write {
		_ = os.WriteFile(path.Join(dir, file), content, 0o644)
	}
}

/*
	Test test vectors
*/

func hashToHash(t *testing.T, h string) hash.Hash {
	t.Helper()

	switch h {
	case "SHA256":
		return hash.SHA256
	case "SHA-256":
		return hash.SHA256
	case "SHA512":
		return hash.SHA512
	case "SHA3-256":
		return hash.SHA3_256
	case "SHA3-512":
		return hash.SHA3_512
	case "SHAKE128":
		return hash.SHAKE128
	case "SHAKE256":
		return hash.SHAKE256
	case "BLAKE2XB":
		return hash.BLAKE2XB
	case "BLAKE2XS":
		return hash.BLAKE2XS
	default:
		t.Fatalf("unknown hash type: %s", h)
	}

	return 0
}

type testVectors []*testVector

func (v *testVector) test(t *testing.T) {
	p := &Parameters{
		Group: v.SuiteID,
		Hash:  hashToHash(t, v.Hash),
	}

	info := p.Init(v.Ida, v.Idb, v.Ad)
	if !bytes.Equal(v.DSI2, info.Dsi2) {
		t.Fatalf("invalid DSI1. Vector %q, got %q", v.DSI2, info.Dsi2)
	}
	if !bytes.Equal(v.DSI2, info.Dsi2) {
		t.Fatalf("invalid DSI2. Vector %q, got %q", v.DSI2, info.Dsi2)
	}

	i := info.new(Initiator)
	r := info.new(Responder)

	var err error

	if err := i.SetScalar(v.InitiatorScalar); err != nil {
		t.Fatalf("error decoding initiator scalar : %v", err)
	}

	if err := r.SetScalar(v.ResponderScalar); err != nil {
		t.Fatalf("error decoding responder scalar : %v", err)
	}

	epku, _, err := i.Start(v.Password, v.Sid)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if !bytes.Equal(v.Epku, epku) {
		t.Fatalf("invalid epku. Vector %q, got %q", v.Epku, epku)
	}

	epks, _, err := r.Start(v.Password, v.Sid)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if !bytes.Equal(v.Epks, epks) {
		t.Fatalf("invalid epks. Vector %q, got %q", v.Epks, epks)
	}

	iSK, err := i.Finish(epks)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if !bytes.Equal(v.SessionKey, iSK) {
		t.Fatalf("invalid initiator session key. Vector %q, got %q", v.SessionKey, iSK)
	}

	rSK, err := r.Finish(epku)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if !bytes.Equal(v.SessionKey, rSK) {
		t.Fatalf("invalid responder session key. Vector %q, got %q", v.SessionKey, rSK)
	}
}

func TestCPaceVectors(t *testing.T) {
	if err := filepath.Walk("tests",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			var v testVectors
			errJSON := json.Unmarshal(contents, &v)
			if errJSON != nil {
				return errJSON
			}

			for _, tv := range v {
				t.Run(fmt.Sprintf("%s - %s", tv.GroupName, tv.Hash), tv.test)
			}
			return nil
		}); err != nil {
		t.Fatalf("error opening test vectors: %v", err)
	}
}
