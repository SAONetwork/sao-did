package did

import (
	"github.com/SaoNetwork/sao-did/key"
	"github.com/SaoNetwork/sao-did/parser"
	"github.com/SaoNetwork/sao-did/sid"
	"github.com/SaoNetwork/sao-did/types"
	"github.com/SaoNetwork/sao-did/util"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/dvsekhvalnov/jose2go/base64url"
	cbornode "github.com/ipfs/go-ipld-cbor"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"
	"github.com/thanhpk/randstr"
	"golang.org/x/xerrors"
	"strings"
	"time"
)

type DidManager struct {
	Id       string
	Provider types.DidProvider
	Resolver types.DidResolver
}

func NewDidManagerWithDid(didString string, qf sid.QueryFunc) (*DidManager, error) {
	did, err := parser.Parse(didString)
	if err != nil {
		return nil, err
	}
	var resolver types.DidResolver
	switch did.Method {
	case key.KeyMethod:
		resolver = key.NewKeyResolver()
	case sid.SidMethod:
		resolver, err = sid.NewSidResolver(qf)
		if err != nil {
			return nil, err
		}
	default:
		return nil, xerrors.New("unsupported method")
	}
	didManager := DidManager{Resolver: resolver}
	didManager.Id = didString
	return &didManager, nil
}

func NewDidManager(provider types.DidProvider, resolver types.DidResolver) DidManager {
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
	jws, err := d.Provider.Authenticate(types.AuthParams{
		Aud:   aud,
		Nonce: nonce,
		Paths: paths,
	})
	if err != nil {
		return "", err
	}

	var payload types.Payload
	err = util.Base64urlToJSON(jws.Payload, &payload)
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

func (d *DidManager) CreateJWS(payload []byte) (types.DagJWS, error) {
	generalJws, err := d.Provider.CreateJWS(payload)
	return generalJws.ToDagJWS(), err
}

func (d *DidManager) VerifyJWS(jws types.GeneralJWS) (string, error) {
	//if (typeof jws !== 'string') jws = fromDagJWS(jws);
	var header types.JWTHeader
	err := util.Base64urlToJSON(jws.Signatures[0].Protected, &header)
	if err != nil {
		return "", xerrors.New("parse JWTHeader failed: " + err.Error())
	}
	kid := header.Kid
	if kid == "" {
		return "", xerrors.New("No kid found in jws")
	}

	if d.Id != "" {
		headerDid, err := parser.Parse(kid)
		if err != nil {
			return "", err
		}
		headerDidStr := strings.Join([]string{"did", headerDid.Method, headerDid.ID}, ":")
		if headerDidStr != d.Id {
			return "", xerrors.Errorf("invalid_jws: signature header's kid is not current did managers.")
		}
	}

	didResolutionResult := d.Resolver.Resolve(kid, types.DidResolutionOptions{})
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

func verifyJWS(jws types.GeneralJWS, pks []types.VerificationMethod) error {
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

func (d *DidManager) CreateDagJWS(
	payload interface{},
	// options: CreateJWSOptions = {}
) (types.DagJWSResult, error) {
	node, err := cbornode.WrapObject(payload, multihash.SHA2_256, multihash.DefaultLengths[multihash.SHA2_256])
	if err != nil {
		return types.DagJWSResult{}, err
	}
	cid := node.Cid()
	linkedBlock := node.RawData()
	payloadCid := base64url.Encode(cid.Bytes())

	//Object.assign(options, { linkedBlock: encodeBase64(linkedBlock) })
	jws, err := d.CreateJWS([]byte(payloadCid)) //, options)
	if err != nil {
		return types.DagJWSResult{}, err
	}

	jws.Link = &cid

	//if (this._capability) {
	//const cacaoBlock = await CacaoBlock.fromCacao(this._capability)
	//return DagJWSResult{ jws, linkedBlock, cacaoBlock: cacaoBlock.bytes }
	//}
	return types.DagJWSResult{Jws: jws, LinkedBlock: linkedBlock}, nil
}
