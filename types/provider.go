package types

import (
	"github.com/SaoNetwork/sao-did/util"
	"github.com/ipfs/go-cid"
	"golang.org/x/xerrors"
)

type AuthParams struct {
	Paths []string
	Nonce string
	Aud   string
}

type GeneralJWS struct {
	Payload    string
	Signatures []JwsSignature
}

func (g GeneralJWS) ToDagJWS() DagJWS {
	return DagJWS{
		Payload:    g.Payload,
		Signatures: g.Signatures,
		Link:       nil,
	}
}

type JwsSignature struct {
	Protected string
	Signature string
}

func (g JwsSignature) GetKid() (string, error) {
	var header JWTHeader
	err := util.Base64urlToJSON(g.Protected, &header)
	if err != nil {
		return "", xerrors.New("parse JWTHeader failed: " + err.Error())
	}
	kid := header.Kid
	if kid == "" {
		return "", xerrors.New("missing kid")
	}
	return kid, nil

	//headerDid, err := parser.Parse(kid)
	//if err != nil {
	//	return "", err
	//}
	//return strings.Join([]string{"did", headerDid.Method, headerDid.ID}, ":"), nil
}

type DagJWSResult struct {
	Jws         DagJWS
	LinkedBlock []byte
	CacaoBlock  []byte
}

type DagJWS struct {
	Payload    string
	Signatures []JwsSignature
	Link       *cid.Cid
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
