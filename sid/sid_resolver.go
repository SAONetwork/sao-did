package sid

import (
	"fmt"
	"strings"

	"github.com/SaoNetwork/sao-did/parser"
	saotypes "github.com/SaoNetwork/sao-did/types"
	consensustypes "github.com/SaoNetwork/sao/x/did/types"
	"github.com/multiformats/go-multibase"
	"golang.org/x/xerrors"
)

const (
	SidMethod      = "sid"
	didLdJson      = "application/did+ld+json"
	didJson        = "application/did+json"
	defaultContext = "https://w3id.org/did/v1"
)

type QueryFunc = func(key string) (*consensustypes.SidDocument, error)

type SidResolver struct {
	query QueryFunc
}

func NewSidResolver(SidDocQuery QueryFunc) (*SidResolver, error) {
	if SidDocQuery == nil {
		return nil, xerrors.New("sid doc query func cannot be empty")
	}
	return &SidResolver{SidDocQuery}, nil
}

func (s *SidResolver) Resolve(sidUrl string, options saotypes.DidResolutionOptions) saotypes.DidResolutionResult {
	sid, err := parser.Parse(sidUrl)
	if err != nil {
		return saotypes.InvalidDidResult
	}
	if sid.Method != SidMethod {
		return saotypes.UnsupportedMethodResult
	}

	result := saotypes.DidResolutionResult{}

	versionId := getVersionInfo(sid.Query)

	sidDoc, err := s.query(versionId)
	if err != nil {
		return saotypes.InvalidDidResult
	}

	if sidDoc == nil {
		return saotypes.InvalidDidResult
	}
	//res.SidDocument.
	result.DidDocument, err = toDidDocument(sidDoc, "did:sid:"+sid.ID)
	if err != nil {
		return saotypes.InvalidDidResult
	}
	result.DidDocumentMetadata.VersionId = versionId

	contentType := didJson
	if options.Accept != "" {
		contentType = options.Accept
	}

	if contentType == didLdJson {
		result.DidDocument.Context = []string{defaultContext}
	} else if contentType == didJson {
	} else {
		return saotypes.RepresentationNotSupportResult
	}

	result.DidResolutionMetadata.ContentType = contentType

	return result
}

func getVersionInfo(query string) string {
	// version-id was changed to versionId in the latest did-core spec
	// https://github.com/w3c/did-core/pull/553
	var versionId string
	for _, q := range strings.Split(query, "&") {
		if strings.Contains(q, "versionId") || strings.Contains(q, "version-id") {
			versionId = strings.Split(q, "=")[1]
			break
		}
	}

	return versionId
}

func toDidDocument(content *consensustypes.SidDocument, did string) (saotypes.DidDocument, error) {
	doc := saotypes.DidDocument{
		Id: did,
	}
	addToDoc := func(keyName string, key string) error {
		encodeType, rawPk, err := multibase.Decode(key)
		if err != nil {
			return err
		}
		if encodeType != multibase.Base58BTC {
			return xerrors.New(fmt.Sprintf("key should decode with base58BTC but get %s", multibase.EncodingToStr[encodeType]))
		}
		// skip varint type (2 bytes)
		publicKeyBase58, err := multibase.Encode(multibase.Base58BTC, rawPk[2:])
		if err != nil {
			return err
		}
		vm := saotypes.VerificationMethod{
			Id:         did + "#" + keyName,
			Controller: did,
			// remove multicodec varint
			PublicKeyBase58: publicKeyBase58[1:],
			// We might want to use 'publicKeyMultibase' here if it
			// ends up in the did-core spec.
		}
		if rawPk[0] == 0xe7 {
			// it's secp256k1
			vm.Type = "EcdsaSecp256k1Signature2019"
			doc.VerificationMethod = append(doc.VerificationMethod, vm)
			doc.Authentication = append(doc.Authentication, vm)
		} else if rawPk[0] == 0xec {
			// it's x25519
			vm.Type = "X25519KeyAgreementKey2019"
			doc.VerificationMethod = append(doc.VerificationMethod, vm)
			doc.KeyAgreement = append(doc.KeyAgreement, vm)
		}
		return nil
	}

	for k, v := range content.Keys {
		err := addToDoc(k, v)
		if err != nil {
			return saotypes.DidDocument{}, err
		}
	}

	return doc, nil
}
