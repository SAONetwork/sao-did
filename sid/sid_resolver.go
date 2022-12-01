package sid

import (
	"context"
	"fmt"
	"strings"

	"github.com/SaoNetwork/sao-did/parser"
	saotypes "github.com/SaoNetwork/sao-did/types"
	"github.com/SaoNetwork/sao/x/did/types"
	"github.com/ignite/cli/ignite/pkg/cosmosclient"
	"github.com/multiformats/go-multibase"
	"golang.org/x/xerrors"
)

const (
	SidMethod      = "sid"
	didLdJson      = "application/did+ld+json"
	didJson        = "application/did+json"
	defaultContext = "https://w3id.org/did/v1"
)

type SidResolver struct {
	didClient types.QueryClient
}

func NewSidResolver(chainAddress string) (*SidResolver, error) {
	cosmos, err := cosmosclient.New(context.TODO(),
		cosmosclient.WithNodeAddress(chainAddress),
		cosmosclient.WithHome("./"),
	)
	if err != nil {
		return nil, err
	}
	client := types.NewQueryClient(cosmos.Context())
	return &SidResolver{client}, nil
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

	res, err := s.didClient.SidDocument(context.Background(), &types.QueryGetSidDocumentRequest{VersionId: versionId})
	if err != nil {
		return saotypes.InvalidDidResult
	}
	//res.SidDocument.
	result.DidDocument, err = toDidDocument(res.SidDocument, "did:sid:"+sid.ID)
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
func toDidDocument(content types.SidDocument, did string) (saotypes.DidDocument, error) {

	doc := saotypes.DidDocument{
		Id: did,
	}

	addToDoc := func(key string) error {
		if len(key) < 15 {
			return xerrors.New(fmt.Sprintf("invalid key length, key : %v", key))
		}
		KeyName := key[len(key)-15:]
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
			Id:         did + "#" + KeyName,
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

	err := addToDoc(content.Signing)
	if err != nil {
		return saotypes.DidDocument{}, err
	}
	err = addToDoc(content.Encryption)
	if err != nil {
		return saotypes.DidDocument{}, err
	}
	return doc, nil
}
