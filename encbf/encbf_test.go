package enc

import (
	"crypto/rand"
	"github.com/alxdavids/bloom-filter/standard"
	"log"
	"math/big"
	"testing"
)

var (
	max int64 = 1000
	n   uint  = 10
	eps       = 0.0001
)

// Default test to catch stupid errors
func TestBloom(t *testing.T) {
	sbf := standard.New(n, eps)

	for i := 0; i < int(n); i++ {
		r, e := rand.Int(rand.Reader, big.NewInt(max))
		if e != nil {
			log.Fatalln(e)
		}
		key := r.Bytes()
		sbf = sbf.Add(key)
	}

	_ = New(sbf.(*standard.StandardBloom))
}
