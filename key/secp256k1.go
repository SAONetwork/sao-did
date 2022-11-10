package key

import (
	"fmt"
	did1 "github.com/SaoNetwork/sao-did/types"
	mbase "github.com/multiformats/go-multibase"
)

type Secp256k1KeyResolver struct {
}

func (s Secp256k1KeyResolver) ResolveKey(pubKeyBytes []byte, fingerprint string) (did1.DidDocument, error) {
	did := fmt.Sprintf("did:key:%s", fingerprint)
	keyId := fmt.Sprintf("%s#%s", did, fingerprint)
	keyMultiBase, err := mbase.Encode(mbase.Base16, pubKeyBytes)
	if err != nil {
		return did1.DidDocument{}, err
	}
	vm := did1.VerificationMethod{
		Id:                 keyId,
		Type:               "Secp256k1VerificationKey2018",
		Controller:         did,
		PublicKeyMultibase: keyMultiBase,
	}
	return did1.DidDocument{
		Id: did,
		VerificationMethod: []did1.VerificationMethod{
			vm,
		},
		Authentication: []any{
			keyId,
		},
	}, nil
}
