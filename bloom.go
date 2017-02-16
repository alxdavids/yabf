package bloom

import (
	"hash"
	"math"
)

type Bloom interface {
	Add(key []byte) Bloom
	Check(key []byte) bool
	SetHasher(hash.Hash)
	Reset()
}

func K(eps float64) uint {
	return uint(math.Floor(math.Log2(1 / eps)))
}

func L(eps float64, n uint) uint {
	return uint(math.Floor(float64(n) * math.Log2(math.E) * math.Log2(1/eps)))
}
