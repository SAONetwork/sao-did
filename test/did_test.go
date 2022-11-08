package test

import (
	"github.com/SaoNetwork/sao-did"
	"github.com/SaoNetwork/sao-did/key"
	cbornode "github.com/ipfs/go-ipld-cbor"
	"github.com/multiformats/go-multihash"
	"testing"
)

type MockProvider struct {
}

func NewMockProvider() *MockProvider {
	return &MockProvider{}
}

func (m *MockProvider) Authenticate(params did.AuthParams) (did.GeneralJWS, error) {
	return did.GeneralJWS{}, nil
}

func (m *MockProvider) CreateJWS(payload []byte) (did.GeneralJWS, error) {
	return did.GeneralJWS{Payload: "234", Signatures: []did.JwsSignature{{Protected: "5678", Signature: "4324"}}}, nil
}

func TestDid(t *testing.T) {
	dm := did.NewDidManager(NewMockProvider(), key.NewKeyResolver())
	a := "asoinegosapng"
	node, err := cbornode.WrapObject(a, multihash.SHA2_256, multihash.DefaultLengths[multihash.SHA2_256])
	jwsResult, err := dm.CreateDagJWS(a)
	if err != nil {
		t.Error(err)
	}
	jws := jwsResult.Jws
	if *jws.Link != node.Cid() ||
		jws.Payload != "234" ||
		jws.Signatures[0].Protected != "5678" ||
		jws.Signatures[0].Signature != "4324" ||
		string(jwsResult.LinkedBlock) != string(node.RawData()) {
		t.Fail()
	}
}
