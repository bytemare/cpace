package cpace

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/stretchr/testify/assert"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/utils"
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
		Group: ciphersuite.Ristretto255Sha512,
		Hash:  hash.SHAKE128,
	}
}

func defaultInitialised() *Parameters {
	return defaultParameters().Init([]byte(testIDInit), []byte(testIDResponder), []byte(testAD))
}

func genTestParams() []*Parameters {
	testGroups := []ciphersuite.Identifier{ciphersuite.Ristretto255Sha512, ciphersuite.Curve25519Sha512, ciphersuite.P256Sha256}
	testHash := []hash.Identifier{hash.SHA256, hash.SHA512, hash.SHAKE128}

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
			assert.NoError(t, err)
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

	csid := utils.RandomBytes(minSidLength)
	ssid := utils.RandomBytes(minSidLength)

	epku, _, err := initiator.Start([]byte(testPassword), csid)
	assert.NoError(t, err)

	epks, _, err := responder.Start([]byte(testPassword), ssid)
	assert.NoError(t, err)

	serverSK, err := responder.Finish(epku)
	assert.NoError(t, err)

	clientSK, err := initiator.Finish(epks)
	assert.NoError(t, err)

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
	assert.NoError(t, err)

	_, _, err = server.Start([]byte(testPassword), sid)
	assert.NoError(t, err)

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

	want = errPeerElementIdentity.Error()
	identity := i.Group.Get(nil).Identity().Bytes()
	if _, err = client.Finish(identity); err == nil || err.Error() != want {
		t.Fatalf(testErrInvalidPeerElementFmt, err, want)
	}
	if _, err = server.Finish(identity); err == nil || err.Error() != want {
		t.Fatalf(testErrInvalidPeerElementFmt, err, want)
	}
}

func assertEqualParameters(t *testing.T, expected, actual *Parameters) {
	assert.Equal(t, expected.Group, actual.Group)
	assert.Equal(t, expected.Hash, actual.Hash)
	assert.Equal(t, expected.Info, actual.Info)
}

func TestParameterSerialization(t *testing.T) {
	p := defaultParameters()
	encodedP := p.Serialize()
	decodedP, err := DeserializeParameters(encodedP)
	assert.NoError(t, err)

	assertEqualParameters(t, p, decodedP)

	p = defaultInitialised()
	encodedP = p.Serialize()
	decodedP, err = DeserializeParameters(encodedP)
	assert.NoError(t, err)

	assertEqualParameters(t, p, decodedP)
}

func TestParameterDeserializationErrors(t *testing.T) {
	// Nil parameter
	var input []byte
	_, err := DeserializeParameters(input)
	assert.EqualError(t, err, errEncodingShort.Error())

	// Short
	input = []byte{1}
	_, err = DeserializeParameters(input)
	assert.EqualError(t, err, errEncodingShort.Error())

	// Non-existent group
	input = []byte{0, 0}
	_, err = DeserializeParameters(input)
	assert.EqualError(t, err, errEncodingCiphersuite.Error())

	// Non-existent hash function
	input = []byte{1, 0}
	_, err = DeserializeParameters(input)
	assert.EqualError(t, err, errEncodingHash.Error())

	// Corrupt Info length
	p := defaultInitialised()
	enc := p.Serialize()
	short := make([]byte, 5)
	copy(short, enc[:5])

	_, err = DeserializeParameters(short)
	assert.Error(t, err)
}

func TestInfoSerialization(t *testing.T) {
	i, err := DeserializeInfo(nil)
	assert.Nil(t, i)
	assert.NoError(t, err)

	i = defaultInitialised().Info

	encoded := i.Serialize()
	decoded, err := DeserializeInfo(encoded)
	assert.NoError(t, err)

	assert.Equal(t, i, decoded)
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
	assert.NoError(t, err)
}

func testInfoFieldDeserializationError(t *testing.T, fullInfo []byte, fieldOffset int) int {
	headerOffset := fieldOffset + encodingLength

	// Missing field (length but no payload)
	sub := make([]byte, encodingLength)
	copy(sub, fullInfo[fieldOffset:headerOffset])
	_, err := DeserializeInfo(sub)
	assert.Error(t, err)

	// Corrupt field (length but short payload)
	l := encoding.OS2IP(fullInfo[fieldOffset:headerOffset])
	subLen := headerOffset + l - 1
	sub = make([]byte, subLen) // shorten
	copy(sub, fullInfo[0:subLen])
	_, err = DeserializeInfo(sub)
	assert.Error(t, err)

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
		tt := tt
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
		_, _, err := c.Start([]byte(testPassword), nil)
		assert.NoError(b, err)
	}
}

func BenchmarkFinish(b *testing.B) {
	c := defaultInitialised().new(Initiator)
	s := defaultInitialised().new(Responder)
	epkc, sid, err := c.Start([]byte(testPassword), nil)
	assert.NoError(b, err)

	_, _, err = s.Start([]byte(testPassword), sid)
	assert.NoError(b, err)

	for i := 0; i < b.N; i++ {
		_, err := s.Finish(epkc)
		assert.NoError(b, err)
	}
}

func BenchmarkFull(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := defaultInitialised().new(Initiator)
		s := defaultInitialised().new(Responder)
		_, err := runCPace(c, s, []byte(testPassword), []byte(testPassword), nil, nil)
		assert.NoError(b, err)
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
	GroupName string                 `json:"HashToGroup"`
	SuiteID   ciphersuite.Identifier `json:"SuiteID"`
	Hash      string                 `json:"Hash"`
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
	sid := utils.RandomBytes(minSidLength)
	sk, err := runCPace(i, r, pwd, pwd, sid, sid)
	assert.NoError(t, err)

	in := input{
		Ida:             ByteToHex(testIDInit),
		Idb:             ByteToHex(testIDResponder),
		Ad:              ByteToHex(testAD),
		Sid:             sid,
		Password:        pwd,
		InitiatorScalar: i.Scalar(),
		ResponderScalar: r.Scalar(),
	}

	out := output{
		DSI1:       info.Dsi1,
		DSI2:       info.Dsi2,
		H2GDst:     ByteToHex(i.group.DST()),
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

	vectors := generateAllVectors(t)
	content, _ := json.MarshalIndent(vectors, "", "  ")
	_ = ioutil.WriteFile(path.Join(dir, file), content, 0o644)
}

/*
	Test test vectors
*/

func hashToHash(h string) hash.Identifier {
	switch h {
	case "SHA256":
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
		return 0
	}
}

type testVectors []*testVector

func (v *testVector) test(t *testing.T) {
	p := &Parameters{
		Group: v.SuiteID,
		Hash:  hashToHash(v.Hash),
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

	if !bytes.Equal(v.H2GDst, []byte(i.group.DST())) {
		t.Fatalf("invalid HashToGroup DST in initiator. Vector %q, got %q", v.H2GDst, []byte(i.group.DST()))
	}
	if !bytes.Equal(v.H2GDst, []byte(r.group.DST())) {
		t.Fatalf("invalid HashToGroup DST in responder. Vector %q, got %q", v.H2GDst, []byte(r.group.DST()))
	}

	var err error

	if err := i.SetScalar(v.InitiatorScalar); err != nil {
		t.Fatalf("error decoding initiator scalar : %v", err)
	}

	if err := r.SetScalar(v.ResponderScalar); err != nil {
		t.Fatalf("error decoding responder scalar : %v", err)
	}

	epku, _, err := i.Start(v.Password, v.Sid)
	assert.NoError(t, err)

	if !bytes.Equal(v.Epku, epku) {
		t.Fatalf("invalid epku. Vector %q, got %q", v.Epku, epku)
	}

	epks, _, err := r.Start(v.Password, v.Sid)
	assert.NoError(t, err)

	if !bytes.Equal(v.Epks, epks) {
		t.Fatalf("invalid epks. Vector %q, got %q", v.Epks, epks)
	}

	iSK, err := i.Finish(epks)
	assert.NoError(t, err)

	if !bytes.Equal(v.SessionKey, iSK) {
		t.Fatalf("invalid initiator session key. Vector %q, got %q", v.SessionKey, iSK)
	}

	rSK, err := r.Finish(epku)
	assert.NoError(t, err)

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

			contents, err := ioutil.ReadFile(path)
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
