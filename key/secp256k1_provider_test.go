package key

import (
	"fmt"
	"sao-did"
	"testing"
)

func TestDid(t *testing.T) {
	didManager := did.DidManager{
		Id:       "1234",
		Provider: NewSecp256k1Provider([]byte("mySecret")),
		Resolver: NewKeyResolver(),
	}
	auth, err := didManager.Authenticate([]string{"path1", "path2", "path3", "path4"}, "aud")
	fmt.Println(auth, err)
	if err != nil {
		t.Fail()
	}
}
