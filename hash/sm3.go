package hash

import (
	"hash"
	"github.com/tjfoc/gmsm/sm3"
)

func New() hash.Hash {
	return sm3.New()
}

func Sum(b []byte) (r [32]byte) {
	copy(r[:],sm3.Sm3Sum(b))
	return
}


