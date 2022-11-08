package key

import (
	did "github.com/SaoNetwork/sao-did"
	"testing"
)

func TestDid(t *testing.T) {
	provider, err := NewSecp256k1Provider([]byte("mySecret"))
	if err != nil {
		t.Error(err)
	}
	didManager := did.DidManager{
		Id:       "1234",
		Provider: provider,
		Resolver: NewKeyResolver(),
	}
	_, err = didManager.Authenticate([]string{"path1", "path2", "path3", "path4"}, "aud")
	if err != nil {
		t.Error(err)
	}
}
