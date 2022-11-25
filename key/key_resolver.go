package key

// https://w3c-ccg.github.io/did-method-key/
import (
	"github.com/SaoNetwork/sao-did/parser"
	saotypes "github.com/SaoNetwork/sao-did/types"
	mbase "github.com/multiformats/go-multibase"
	codec "github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
)

const (
	keyMethod      = "key"
	didLdJson      = "application/did+ld+json"
	didJson        = "application/did+json"
	defaultContext = "https://w3id.org/did/v1"
)

type KeyToDidDocument interface {
	ResolveKey(pubKeyBytes []byte, fingerprint string) (saotypes.DidDocument, error)
}

type KeyResolver struct {
	cryptoResolverMap map[uint64]KeyToDidDocument
}

func NewKeyResolver() *KeyResolver {
	crm := make(map[uint64]KeyToDidDocument)
	crm[uint64(codec.Secp256k1Pub)] = Secp256k1KeyResolver{}
	return &KeyResolver{cryptoResolverMap: crm}
}

func (s *KeyResolver) Resolve(didUrl string, options saotypes.DidResolutionOptions) saotypes.DidResolutionResult {
	did, err := parser.Parse(didUrl)
	if err != nil {
		return saotypes.InvalidDidResult
	}

	if did.Method != keyMethod {
		return saotypes.UnsupportedMethodResult
	}

	_, bytes, err := mbase.Decode(did.ID)
	if err != nil {
		return saotypes.InvalidDidResult
	}

	keyType, n, err := varint.FromUvarint(bytes)
	if err != nil {
		return saotypes.InvalidDidResult
	}
	if n != 2 {
		return saotypes.InvalidDidResult
	}

	if r, ok := s.cryptoResolverMap[keyType]; ok {
		doc, err := r.ResolveKey(bytes[n:], did.ID)
		if err != nil {
			return saotypes.InvalidDidResult
		}

		result := saotypes.DidResolutionResult{}

		contentType := didJson
		if options.Accept != "" {
			contentType = options.Accept
		}

		if contentType == didLdJson {
			doc.Context = []string{defaultContext}
			result.DidDocument = doc
		} else if contentType == didJson {
			result.DidDocument = doc
		} else {
			return saotypes.RepresentationNotSupportResult
		}
		return result
	} else {
		return saotypes.InvalidDidResult
	}
}
