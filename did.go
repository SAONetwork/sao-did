package did

import (
	"encoding/json"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/dvsekhvalnov/jose2go/base64url"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multibase"
	"github.com/thanhpk/randstr"
	"golang.org/x/xerrors"
	"strings"
	"time"
)

type DidManager struct {
	Id       string
	Provider DidProvider
	Resolver DidResolver
}

func NewDidManager(provider DidProvider, resolver DidResolver) DidManager {
	return DidManager{
		Provider: provider,
		Resolver: resolver,
	}
}

func (d *DidManager) Authenticate(paths []string, aud string) (string, error) {
	if d.Provider == nil {
		return "", xerrors.New("provider is missing.")
	}
	if d.Resolver == nil {
		return "", xerrors.New("resolver is missing.")
	}
	nonce := randstr.String(16)
	jws, err := d.Provider.Authenticate(AuthParams{
		Aud:   aud,
		Nonce: nonce,
		Paths: paths,
	})
	if err != nil {
		return "", err
	}

	var payload Payload
	err = base64urlToJSON(jws.Payload, &payload)
	if err != nil {
		return "", xerrors.New("parse payload failed: " + err.Error())
	}

	kid, err := d.VerifyJWS(jws)
	if err != nil {
		return "", xerrors.New("verifyJWS failed: " + err.Error())
	}
	if !strings.Contains(kid, payload.Did) {
		return "", xerrors.New("Invalid authencation response, kid mismatch")
	}
	if payload.Nonce != nonce {
		return "", xerrors.New("Invalid authencation response, wrong nonce")
	}
	if payload.Aud != aud {
		return "", xerrors.New("Invalid authencation response, wrong aud")
	}
	if payload.Exp < time.Now().Unix() {
		return "", xerrors.New("Invalid authencation response, expired")
	}
	d.Id = payload.Did
	return payload.Did, nil
}

func (d *DidManager) CreateJWS(payload []byte) (GeneralJWS, error) {
	return d.Provider.CreateJWS(payload)
}

func (d *DidManager) VerifyJWS(jws GeneralJWS) (string, error) {
	//if (typeof jws !== 'string') jws = fromDagJWS(jws);
	var header JWTHeader
	err := base64urlToJSON(jws.Signatures[0].Protected, &header)
	if err != nil {
		return "", xerrors.New("parse JWTHeader failed: " + err.Error())
	}
	kid := header.Kid
	if kid == "" {
		return "", xerrors.New("No kid found in jws")
	}

	didResolutionResult := d.Resolver.Resolve(kid, DidResolutionOptions{})
	nextUpdate := didResolutionResult.DidDocumentMetadata.NextUpdate
	if nextUpdate != "" {
		// This version of the DID document has been revoked. Check if the JWS
		// was signed before the revocation happened.
		revocationTime, err := time.Parse(time.RFC3339, nextUpdate)
		if err != nil {
			return "", xerrors.New("nextUpdate should be RFC3339 format" + err.Error())
		}
		if time.Now().After(revocationTime) {
			// Do not allow using a key _after_ it is being revoked
			return "", xerrors.New("invalid_jws: signature authored with a revoked DID version: " + kid)
		}
	}
	// Key used before `updated` date
	updated := didResolutionResult.DidDocumentMetadata.Updated
	if updated != "" {
		updatedTime, err := time.Parse(time.RFC3339, updated)
		if err != nil {
			return "", xerrors.New("Updated should be RFC3339 format" + err.Error())
		}
		if time.Now().Before(updatedTime) {
			return "", xerrors.New("invalid_jws: signature authored before creation of DID version: ${kid}")
		}
	}
	publicKeys := didResolutionResult.DidDocument.VerificationMethod
	// verifyJWS will throw an error if the signature is invalid
	err = verifyJWS(jws, publicKeys)
	if err != nil {
		return kid, xerrors.New("verify JWS failed: " + err.Error())
	}
	//var payload Payload
	//base64urlToJSON(jws.Payload, payload);
	// If an error is thrown it means that the payload is a CID.

	return kid, nil
}

func base64urlToJSON(str string, v any) error {
	bytes, err := base64url.Decode(str)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, v)
}

func verifyJWS(jws GeneralJWS, pks []VerificationMethod) error {
	data := jws.Signatures[0].Protected + "." + jws.Payload

	rawSig, err := base64url.Decode(jws.Signatures[0].Signature)
	if err != nil {
		return xerrors.New("raw signature decode failed:" + err.Error())
	}

	var rawPk []byte
	for _, pk := range pks {
		//pk.Type
		if pk.PublicKeyBase58 != "" {
			rawPk, err = base58.Decode(pk.PublicKeyBase58)
		} else if pk.PublicKeyMultibase != "" {
			_, rawPk, err = multibase.Decode(pk.PublicKeyMultibase)
		}
		if err != nil {
			return xerrors.Errorf("decode pubKey failed: %v", err)
		}

		if rawPk != nil {
			pubkey := secp256k1.PubKey{rawPk}

			if pubkey.VerifySignature([]byte(data), rawSig) {
				return nil
			}
		}
	}
	return xerrors.New("invalid_signature: Signature invalid for JWT")
}
