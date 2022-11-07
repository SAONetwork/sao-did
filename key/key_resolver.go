package key

// https://w3c-ccg.github.io/did-method-key/
import (
	did2 "github.com/SaoNetwork/sao-did"
	mbase "github.com/multiformats/go-multibase"
	codec "github.com/multiformats/go-multicodec"
	varint "github.com/multiformats/go-varint"
	"github.com/ockam-network/did"
)

const (
	keyMethod      = "key"
	didLdJson      = "application/did+ld+json"
	didJson        = "application/did+json"
	defaultContext = "https://w3id.org/did/v1"
)

type KeyToDidDocument interface {
	ResolveKey(pubKeyBytes []byte, fingerprint string) (did2.DidDocument, error)
}

type KeyResolver struct {
	cryptoResolverMap map[uint64]KeyToDidDocument
}

func NewKeyResolver() KeyResolver {
	crm := make(map[uint64]KeyToDidDocument)
	crm[uint64(codec.Secp256k1Pub)] = Secp256k1KeyResolver{}
	return KeyResolver{cryptoResolverMap: crm}
}

func (s *KeyResolver) Resolve(didUrl string, options did2.DidResolutionOptions) did2.DidResolutionResult {
	did, err := did.Parse(didUrl)
	if err != nil {
		return did2.InvalidDidResult
	}

	if did.Method != keyMethod {
		return did2.UnsupportedMethodResult
	}

	_, bytes, err := mbase.Decode(did.ID)
	if err != nil {
		return did2.InvalidDidResult
	}

	keyType, n, err := varint.FromUvarint(bytes)
	if err != nil {
		return did2.InvalidDidResult
	}
	if n != 2 {
		return did2.InvalidDidResult
	}

	if r, ok := s.cryptoResolverMap[keyType]; ok {
		doc, err := r.ResolveKey(bytes[n:], did.ID)
		if err != nil {
			return did2.InvalidDidResult
		}

		result := did2.DidResolutionResult{}

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
			return did2.RepresentationNotSupportResult
		}
		return result
	} else {
		return did2.InvalidDidResult
	}
}
