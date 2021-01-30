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
	"testing"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/utils"
)

const (
	testIDInit      = "initiator"
	testIDResponder = "responder"
	testAD          = "ad"
	testPassword    = "password"
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

func defaultInfo() *Info {
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
			p[i] = &Parameters{g, h}
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
			client := info.New(Initiator)
			server := info.New(Responder)
			_, err := runCPace(client, server, []byte(testPassword), []byte(testPassword), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCPaceResponderNilSid(t *testing.T) {
	i := defaultInfo()
	s := i.New(Responder)
	if _, _, err := s.Start([]byte(testPassword), nil); err == nil || err.Error() != errSetupSIDNil.Error() {
		t.Fatalf("expected error on nil sid for responder. Got %q, want %q", err, errSetupSIDNil)
	}
}

func TestCPaceShortSid(t *testing.T) {
	i := defaultInfo()
	sid := []byte("short sid")
	client := i.New(Initiator)
	server := i.New(Responder)
	if _, _, err := client.Start([]byte(testPassword), sid); err == nil || err.Error() != errSetupSIDTooShort.Error() {
		t.Fatalf("expected error on nil sid for responder. Got %q, want %q", err, errSetupSIDTooShort)
	}
	if _, _, err := server.Start([]byte(testPassword), sid); err == nil || err.Error() != errSetupSIDTooShort.Error() {
		t.Fatalf("expected error on nil sid for responder. Got %q, want %q", err, errSetupSIDTooShort)
	}
}

func TestCPaceWrongSid(t *testing.T) {
	i := defaultInfo()
	initiator := i.New(Initiator)
	responder := i.New(Responder)

	csid := utils.RandomBytes(minSidLength)
	ssid := utils.RandomBytes(minSidLength)

	epku, _, err := initiator.Start([]byte(testPassword), csid)
	if err != nil {
		t.Fatal(err)
	}

	epks, _, err := responder.Start([]byte(testPassword), ssid)
	if err != nil {
		t.Fatal(err)
	}

	serverSK, err := responder.Finish(epku)
	if err != nil {
		t.Fatal(err)
	}

	clientSK, err := initiator.Finish(epks)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(serverSK, clientSK) {
		t.Fatal("Client and server keys are supposed to be different (different sid)")
	}
}

func TestCPaceEmptyShare(t *testing.T) {
	i := defaultInfo()
	client := i.New(Initiator)
	server := i.New(Responder)

	if _, err := client.Finish(nil); err == nil || err.Error() != errNoEphemeralPubKey.Error() {
		t.Fatalf("expected error on empty own public key. Got %q, want %q", err, errNoEphemeralPubKey)
	}
	if _, err := server.Finish(nil); err == nil || err.Error() != errNoEphemeralPubKey.Error() {
		t.Fatalf("expected error on empty own public key. Got %q, want %q", err, errNoEphemeralPubKey)
	}
}

func TestCPacePeerElement(t *testing.T) {
	i := defaultInfo()
	client := i.New(Initiator)
	server := i.New(Responder)
	emptyPeerElement := []byte("")

	_, sid, err := client.Start([]byte(testPassword), nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = server.Start([]byte(testPassword), sid)
	if err != nil {
		t.Fatal(err)
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
		t.Fatalf("expected error on invalid peerElement. Got %q, want %q", err, want)
	}
	if _, err = server.Finish(invalidPeerElement); err == nil || err.Error() != want {
		t.Fatalf("expected error on invalid peerElement. Got %q, want %q", err, want)
	}

	want = errPeerElementIdentity.Error()
	identity := i.Parameters.Group.Get(nil).Identity().Bytes()
	if _, err = client.Finish(identity); err == nil || err.Error() != want {
		t.Fatalf("expected error on invalid peerElement. Got %q, want %q", err, want)
	}
	if _, err = server.Finish(identity); err == nil || err.Error() != want {
		t.Fatalf("expected error on invalid peerElement. Got %q, want %q", err, want)
	}
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
			c := p.Init([]byte(tt.IDa), []byte(tt.IDb), []byte(tt.AdA)).New(Initiator)
			s := p.Init([]byte(tt.IDa), []byte(tt.IDb), []byte(tt.AdB)).New(Responder)

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
		_ = defaultInfo().New(Initiator)
	}
}

func BenchmarkStart(b *testing.B) {
	c := defaultInfo().New(Initiator)

	for i := 0; i < b.N; i++ {
		_, _, err := c.Start([]byte(testPassword), nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFinish(b *testing.B) {
	c := defaultInfo().New(Initiator)
	s := defaultInfo().New(Responder)
	epkc, sid, err := c.Start([]byte(testPassword), nil)
	if err != nil {
		b.Fatal(err)
	}

	_, _, err = s.Start([]byte(testPassword), sid)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_, err := s.Finish(epkc)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFull(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := defaultInfo().New(Initiator)
		s := defaultInfo().New(Responder)
		_, err := runCPace(c, s, []byte(testPassword), []byte(testPassword), nil, nil)
		if err != nil {
			b.Fatal(err)
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

	i := params.Init([]byte(testIDInit),
		[]byte(testIDResponder),
		[]byte(testAD))
	c := i.New(Initiator)
	s := i.New(Responder)
	pwd := []byte(testPassword)
	sid := utils.RandomBytes(minSidLength)
	sk, err := runCPace(c, s, pwd, pwd, sid, sid)
	if err != nil {
		t.Fatal(err)
	}

	in := input{
		Ida:             []byte(testIDInit),
		Idb:             []byte(testIDResponder),
		Ad:              []byte(testAD),
		Sid:             sid,
		Password:        pwd,
		InitiatorScalar: c.secret.Bytes(),
		ResponderScalar: s.secret.Bytes(),
	}

	out := output{
		DSI1:       i.Dsi1,
		DSI2:       i.Dsi2,
		H2GDst:     []byte(c.group.DST()),
		Epku:       c.epk,
		Epks:       s.epk,
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

	i := p.Init(v.Ida, v.Idb, v.Ad)
	if !bytes.Equal(v.DSI2, i.Dsi2) {
		t.Fatalf("invalid DSI1. Vector %q, got %q", v.DSI2, i.Dsi2)
	}
	if !bytes.Equal(v.DSI2, i.Dsi2) {
		t.Fatalf("invalid DSI2. Vector %q, got %q", v.DSI2, i.Dsi2)
	}

	c := i.New(Initiator)
	s := i.New(Responder)

	if !bytes.Equal(v.H2GDst, []byte(c.group.DST())) {
		t.Fatalf("invalid HashToGroup DST in initiator. Vector %q, got %q", v.H2GDst, []byte(c.group.DST()))
	}
	if !bytes.Equal(v.H2GDst, []byte(s.group.DST())) {
		t.Fatalf("invalid HashToGroup DST in responder. Vector %q, got %q", v.H2GDst, []byte(s.group.DST()))
	}

	var err error

	c.secret, err = c.group.NewScalar().Decode(v.InitiatorScalar)
	if err != nil {
		t.Fatalf("error decoding initiator scalar : %v", err)
	}

	s.secret, err = c.group.NewScalar().Decode(v.ResponderScalar)
	if err != nil {
		t.Fatalf("error decoding responder scalar : %v", err)
	}

	epku, _, err := c.Start(v.Password, v.Sid)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(v.Epku, epku) {
		t.Fatalf("invalid epku. Vector %q, got %q", v.Epku, epku)
	}

	epks, _, err := s.Start(v.Password, v.Sid)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(v.Epks, epks) {
		t.Fatalf("invalid epks. Vector %q, got %q", v.Epks, epks)
	}

	iSK, err := c.Finish(epks)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(v.SessionKey, iSK) {
		t.Fatalf("invalid initiator session key. Vector %q, got %q", v.SessionKey, iSK)
	}

	rSK, err := s.Finish(epku)
	if err != nil {
		t.Fatal(err)
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

			file, errOpen := os.Open(path)
			if errOpen != nil {
				return errOpen
			}

			defer file.Close()

			val, errRead := ioutil.ReadAll(file)
			if errRead != nil {
				return errRead
			}

			var v testVectors
			errJSON := json.Unmarshal(val, &v)
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
