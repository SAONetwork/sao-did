package key

import (
	"fmt"
	mbase "github.com/multiformats/go-multibase"
	"sao-did"
)

type Secp256k1KeyResolver struct {
}

func (s Secp256k1KeyResolver) ResolveKey(pubKeyBytes []byte, fingerprint string) (did.DidDocument, error) {
	did := fmt.Sprintf("did:key:%s", fingerprint)
	keyId := fmt.Sprintf("%s#%s", did, fingerprint)
	keyMultiBase, err := mbase.Encode(mbase.Base16, pubKeyBytes)
	if err != nil {
		return did.DidDocument{}, err
	}
	vm := did.VerificationMethod{
		Id:                 keyId,
		Type:               "Secp256k1VerificationKey2018",
		Controller:         did,
		PublicKeyMultibase: keyMultiBase,
	}
	return did.DidDocument{
		Id: did,
		VerificationMethod: []did.VerificationMethod{
			vm,
		},
		Authentication: []any{
			keyId,
		},
	}, nil
}
