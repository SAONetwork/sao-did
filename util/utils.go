package util

import (
	"encoding/json"
	"github.com/SaoNetwork/sao-did/parser"
	"github.com/dvsekhvalnov/jose2go/base64url"
	"strings"
)

func Base64urlToJSON(str string, v any) error {
	bytes, err := base64url.Decode(str)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, v)
}

func KidToDid(kid string) (string, error) {
	headerDid, err := parser.Parse(kid)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{"did", headerDid.Method, headerDid.ID}, ":"), nil
}
