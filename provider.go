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

type Payload struct {
	Did   string
	Aud   string
	Nonce string
	Paths []string
	Exp   int64
}

type DidProvider interface {
	Authenticate(params AuthParams) GeneralJWS
	Sign(payload []byte) GeneralJWS
}
