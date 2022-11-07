package did

import (
	"github.com/thanhpk/randstr"
	"golang.org/x/xerrors"
)

type DidManager struct {
	Id       string
	Provider DidProvider
	Resolver DidResolver
}

func (d DidManager) authenticate(paths []string, aud string) (GeneralJWS, error) {
	if d.Provider == nil {
		return GeneralJWS{}, xerrors.New("provider is missing.")
	}
	if d.Resolver == nil {
		return GeneralJWS{}, xerrors.New("resolver is missing.")
	}
	nonce := randstr.String(16)
	jws := d.Provider.Authenticate(AuthParams{
		Aud:   aud,
		Nonce: nonce,
		Paths: paths,
	})
	return jws, nil
}
