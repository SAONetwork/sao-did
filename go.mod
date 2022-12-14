module github.com/SaoNetwork/sao-did

go 1.18

require (
	github.com/dvsekhvalnov/jose2go v1.5.0
	github.com/ipfs/go-cid v0.3.2
	github.com/ipfs/go-ipld-cbor v0.0.6
	github.com/multiformats/go-multibase v0.1.1
	github.com/multiformats/go-multicodec v0.7.0
	github.com/multiformats/go-multihash v0.2.1
	github.com/multiformats/go-varint v0.0.6
	github.com/thanhpk/randstr v1.0.4
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2
)

require (
	cloud.google.com/go/storage v1.27.0 // indirect
	cosmossdk.io/errors v1.0.0-beta.7 // indirect
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/btcsuite/btcd v0.22.1 // indirect
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1-0.20200219035652-afde56e7acac // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.5.1 // indirect
	github.com/gogo/protobuf v1.3.3 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/gofuzz v1.0.0 // indirect
	github.com/ipfs/go-block-format v0.0.2 // indirect
	github.com/ipfs/go-ipfs-util v0.0.1 // indirect
	github.com/ipfs/go-ipld-format v0.0.1 // indirect
	github.com/klauspost/cpuid/v2 v2.1.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/polydawn/refmt v0.0.0-20201211092308-30ac6d18308e // indirect
	github.com/prometheus/common v0.37.0 // indirect
	github.com/sasha-s/go-deadlock v0.3.1 // indirect
	github.com/smartystreets/goconvey v1.6.4 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/tendermint/go-amino v0.16.0 // indirect
	github.com/tendermint/tendermint v0.34.23 // indirect
	github.com/warpfork/go-wish v0.0.0-20200122115046-b9ea61034e4a // indirect
	github.com/whyrusleeping/cbor-gen v0.0.0-20200123233031-1cdf64d27158 // indirect
	github.com/zondax/hid v0.9.1-0.20220302062450-5552068d2266 // indirect
	golang.org/x/crypto v0.1.0 // indirect
	golang.org/x/net v0.2.0 // indirect
	golang.org/x/oauth2 v0.2.0 // indirect
	golang.org/x/sys v0.2.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	google.golang.org/api v0.102.0 // indirect
	google.golang.org/genproto v0.0.0-20221114212237-e4508ebdbee1 // indirect
	google.golang.org/grpc v1.50.1 // indirect
	google.golang.org/protobuf v1.28.2-0.20220831092852-f930b1dc76e8 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	lukechampine.com/blake3 v1.1.7 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

require (
	github.com/cosmos/cosmos-sdk v0.46.6
	github.com/mr-tron/base58 v1.2.0
	github.com/multiformats/go-base32 v0.0.4 // indirect
	github.com/multiformats/go-base36 v0.1.0 // indirect
)

replace github.com/SaoNetwork/sao => ../sao-consensus

replace github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1
