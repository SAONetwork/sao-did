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

func (d DidManager) authenticate(paths []string, aud string) (string, error) {
	if d.Provider == nil {
		return "", xerrors.New("provider is missing.")
	}
	if d.Resolver == nil {
		return "", xerrors.New("resolver is missing.")
	}
	nonce := randstr.String(16)
	jws := d.Provider.Authenticate(AuthParams{
		aud:   aud,
		nonce: nonce,
		paths: paths,
	})

}
