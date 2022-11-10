package key

import (
	"encoding/json"
	"fmt"
	saodid "github.com/SaoNetwork/sao-did/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/dvsekhvalnov/jose2go/base64url"
	"github.com/multiformats/go-multibase"
	"strings"
	"time"
)

type Secp256k1Provider struct {
	did       string
	secretKey []byte
}

func NewSecp256k1Provider(secretKey []byte) (*Secp256k1Provider, error) {
	privKey := secp256k1.GenPrivKeyFromSecret(secretKey)
	pubKey := privKey.PubKey()

	did, err := encodeDid(pubKey.Bytes())
	if err != nil {
		return nil, err
	}
	return &Secp256k1Provider{did, secretKey}, nil
}

func encodeDid(pubKey []byte) (string, error) {
	bytes := append([]byte{0xe7, 0x01}, pubKey...)
	encoded, err := multibase.Encode(multibase.Base58BTC, bytes)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("did:key:" + encoded), nil
}

func (s *Secp256k1Provider) Authenticate(params saodid.AuthParams) (saodid.GeneralJWS, error) {
	payload := saodid.Payload{
		s.did,
		params.Aud,
		params.Nonce,
		params.Paths,
		time.Now().Unix() + 600,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return saodid.GeneralJWS{}, err
	}
	return s.CreateJWS(payloadBytes)
}

func (s *Secp256k1Provider) CreateJWS(
	payload []byte,
) (saodid.GeneralJWS, error) {
	splits := strings.Split(s.did, ":")
	kid := s.did + "#" + splits[2]
	signer := secp256k1.GenPrivKeyFromSecret(s.secretKey)
	return createJWS(payload, signer, saodid.JWTHeader{Kid: kid, Alg: "ES256K"})
}

func createJWS(
	payload []byte,
	signer *secp256k1.PrivKey,
	header saodid.JWTHeader,
) (saodid.GeneralJWS, error) {
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return saodid.GeneralJWS{}, err
	}
	encodedPayload := encodeSection(payload)
	protectedHeader := encodeSection(headerBytes)
	input := protectedHeader + "." + encodedPayload
	sig, err := signer.Sign([]byte(input))
	if err != nil {
		return saodid.GeneralJWS{}, err
	}
	return saodid.GeneralJWS{
		encodedPayload,
		[]saodid.JwsSignature{{
			Protected: protectedHeader,
			Signature: encodeSection(sig),
		}},
	}, nil
}

func encodeSection(data []byte) string {
	return base64url.Encode(data)
}
