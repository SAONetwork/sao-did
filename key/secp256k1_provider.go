package key

import (
	secp256k1 "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	did "sao-did"
)

type Secp256k1Provider struct {
}

func NewSecp256k1Provider(seed []byte) {
	privKey := secp256k1.GenPrivKeyFromSecret(seed)
	pubKey := privKey.PubKey()
	addr := pubKey.Address()
	addr.Bytes()
}

func encodeDid(pubKey []byte) string {
}

func (s Secp256k1Provider) Authenticate(params did.AuthParams) did.GeneralJWS {
}
