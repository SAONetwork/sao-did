package did

const (
	InvalidDid                 = "invalidDid"
	NotFound                   = "notFound"
	RepresentationNotSupported = "representationNotSupported"
	UnsupportedMethod          = "unsupportedMethod"
)

var InvalidDidResult = DidResolutionResult{
	DidResolutionMetadata: DidResolutionMetadata{Error: InvalidDid},
}

var RepresentationNotSupportResult = DidResolutionResult{
	DidResolutionMetadata: DidResolutionMetadata{Error: RepresentationNotSupported},
}

var UnsupportedMethodResult = DidResolutionResult{
	DidResolutionMetadata: DidResolutionMetadata{Error: UnsupportedMethod},
}

type DidResolutionResult struct {
	DidResolutionMetadata DidResolutionMetadata
	DidDocument           DidDocument
	DidDocumentMetadata   DidDocumentMetadata
}

type DidResolutionMetadata struct {
	ContentType string
	Error       string
}

type DidDocument struct {
	Context            []string `json:"@context"`
	Id                 string
	AlsoKnownAs        []string
	Controller         []string
	VerificationMethod []VerificationMethod
	//Service            []Service
	Authentication []any
}

type VerificationMethod struct {
	Id                 string
	Type               string
	Controller         string
	PublicKeyBase58    string
	PublicKeyMultibase string
}

type DidDocumentMetadata struct {
	Created       string
	Updated       string
	Deactivated   bool
	NextUpdate    string
	VersionId     string
	NextVersionId string
	EquivalentId  string
}

type DidResolutionOptions struct {
	Accept string
}

type DidResolver interface {
	Resolve(didUrl string, options DidResolutionOptions) DidResolutionResult
}
