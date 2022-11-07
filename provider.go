package did

type AuthParams struct {
	Paths []string
	Nonce string
	Aud   string
}

type GeneralJWS struct {
	Payload    string
	Signatures []JwsSignature
}

type JwsSignature struct {
	Protected string
	Signature string
}

type JWTHeader struct {
	Kid string
	Alg string
}

type DidProvider interface {
	Authenticate(params AuthParams) GeneralJWS
	Sign(payload []byte)
}
