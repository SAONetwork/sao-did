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
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

type Payload struct {
	Did   string   `json:"did"`
	Aud   string   `json:"aud"`
	Nonce string   `json:"nonce"`
	Paths []string `json:"paths"`
	Exp   int64    `json:"exp"`
}

type DidProvider interface {
	Authenticate(params AuthParams) (GeneralJWS, error)
	CreateJWS(payload []byte) (GeneralJWS, error)
}
