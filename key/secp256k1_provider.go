package key

import (
	"encoding/json"
	"fmt"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/dvsekhvalnov/jose2go/base64url"
	"github.com/multiformats/go-multibase"
	"strings"

	did1 "github.com/SaoNetwork/sao-did"
)

type Secp256k1Provider struct {
	did       string
	secretKey []byte
}

func NewSecp256k1Provider(seed []byte) Secp256k1Provider {
	privKey := secp256k1.GenPrivKeyFromSecret(seed)
	pubKey := privKey.PubKey()
	addr := pubKey.Address()

	did, _ := encodeDid(addr.Bytes())
	return Secp256k1Provider{did, seed}
}

func encodeDid(pubKey []byte) (string, error) {
	bytes := append([]byte{0xe7, 0x01}, pubKey...)
	encoded, err := multibase.Encode(multibase.Base58BTC, bytes)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("did:key:" + encoded), nil
}

type Payload struct {
	Did   string
	Aud   string
	Nonce string
	Paths []string
}

func (s Secp256k1Provider) Authenticate(params did1.AuthParams) did1.GeneralJWS {
	payload := Payload{
		s.did,
		params.Aud,
		params.Nonce,
		params.Paths,
	}
	payloadBytes, _ := json.Marshal(payload)
	return s.Sign(payloadBytes)
}

func (s Secp256k1Provider) Sign(
	payload []byte,
) did1.GeneralJWS {
	splits := strings.Split(s.did, ":")
	kid := s.did + "#" + splits[2]
	signer := secp256k1.GenPrivKeyFromSecret(s.secretKey)
	return createJWS(payload, signer, did1.JWTHeader{Kid: kid, Alg: "ES256K"})
}

func createJWS(
	payload []byte,
	signer *secp256k1.PrivKey,
	header did1.JWTHeader,
) did1.GeneralJWS {
	headerBytes, _ := json.Marshal(header)
	encodedPayload := encodeSection(payload)
	protectedHeader := encodeSection(headerBytes)
	input := encodedPayload + "." + encodedPayload
	sig, err := signer.Sign([]byte(input))
	if err != nil {
		return did1.GeneralJWS{}
	}
	return did1.GeneralJWS{encodedPayload, []did1.JwsSignature{{
		Protected: protectedHeader,
		Signature: encodeSection(sig),
	}}}
}

func encodeSection(data []byte) string {
	return base64url.Encode(data)
}
