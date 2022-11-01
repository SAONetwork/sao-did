package did

type AuthParams struct {
	paths []string
	nonce string
	aud   string
}

type GeneralJWS struct {
	Payload    string
	Signatures []JwsSignature
}

type JwsSignature struct {
	Protected string
	Signature string
}

type DidProvider interface {
	Authenticate(params AuthParams) GeneralJWS
}
