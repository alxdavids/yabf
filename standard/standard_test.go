package standard

import (
	"crypto/rand"
	"log"
	"math/big"
	"testing"
)

var (
	max int64 = 1000
	n   uint  = 100
	eps       = 0.0001
)

func TestBloom(t *testing.T) {
	sbf := New(n, eps)
	r, e := rand.Int(rand.Reader, big.NewInt(max))
	if e != nil {
		log.Fatalln(e)
	}
	key := r.Bytes()
	sbf = sbf.Add(key)

	if !sbf.Check(key) {
		log.Fatalln("Key not found in Bloom filter")
	}

	r2, _ := rand.Int(rand.Reader, big.NewInt(max))
	key2 := r2.Bytes()
	if sbf.Check(key2) {
		log.Fatalln("Incorrect key found in Bloom filter")
	}
}
