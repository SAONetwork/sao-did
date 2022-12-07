package util

import (
	"encoding/json"
	"github.com/dvsekhvalnov/jose2go/base64url"
)

func Base64urlToJSON(str string, v any) error {
	bytes, err := base64url.Decode(str)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, v)
}
