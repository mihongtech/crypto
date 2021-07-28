package hash

import (
	"crypto/sha256"
	"github.com/mihongtech/crypto/util"
	"github.com/tjfoc/gmsm/sm3"
	"hash"
)

func New() hash.Hash {
	if util.HashIsSM() {
		return sm3.New()
	}
	return sha256.New()
}

func Sum(b []byte) (r [32]byte) {
	if util.HashIsSM() {
		copy(r[:], sm3.Sm3Sum(b))
		return
	}
	return sha256.Sum256(b)
}
