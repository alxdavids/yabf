package encbf

import (
	"crypto/rand"
	"github.com/alxdavids/bloom-filter/standard"
	"github.com/mcornejo/go-go-gadget-paillier"
	"log"
	"math/big"
	"testing"
	"xojoc.pw/bitset"
)

var (
	max     int64 = 1000
	n       uint  = 10
	maxConc int   = 5
	eps           = 0.0001
	keySize       = 512
)

// Default test to catch stupid errors
func TestEncBloom(t *testing.T) {
	sbf := standard.New(n, eps)

	for i := 0; i < int(n); i++ {
		r, e := rand.Int(rand.Reader, big.NewInt(max))
		if e != nil {
			log.Fatalln(e)
		}
		key := r.Bytes()
		sbf = sbf.Add(key)
	}

	eblof := New(sbf.(*standard.StandardBloom), keySize, 0, maxConc).(*EncBloom)
	decBf := &bitset.BitSet{}
	for i, v := range eblof.ebf {
		m, e := paillier.Decrypt(eblof.priv, v.Bytes())
		if e != nil {
			log.Fatalln(e)
		}

		mInt := new(big.Int).SetBytes(m)
		if big.NewInt(1).Cmp(mInt) == 0 {
			decBf.Set(i)
		}
	}

	// Invert bloom filter
	decBf.ToggleRange(0, int(eblof.L))
	if !decBf.Equal(eblof.bf) {
		log.Println(decBf)
		log.Println(eblof.bf)
		log.Fatalln("Decrypted Bloom filter is not equal")
	}
}

func TestOps(t *testing.T) {
	sbf := standard.New(n, eps)

	keys := make([]*big.Int, int(n))
	for i := 0; i < int(n); i++ {
		r, e := rand.Int(rand.Reader, big.NewInt(max))
		if e != nil {
			log.Fatalln(e)
		}
		keys[i] = r
		key := r.Bytes()
		sbf = sbf.Add(key)
	}

	eblof := New(sbf.(*standard.StandardBloom), keySize, 0, maxConc).(*EncBloom)
	unionTest(keys, eblof)

	//reset array and do intersection
	eblof = New(sbf.(*standard.StandardBloom), keySize, 1, maxConc).(*EncBloom)
	interTest(keys, eblof)

	//reset array and do intersection
	eblof = New(sbf.(*standard.StandardBloom), keySize, 2, maxConc).(*EncBloom)
	caTest(keys, eblof)
}

func unionTest(keys []*big.Int, eblof *EncBloom) {
	// Check elements that already exist
	for _, v := range keys {
		eblof.Check(v.Bytes())
	}
	eblof.HomCombine()

	for i := range eblof.ca {
		pair := eblof.ca[i]

		m0, e := paillier.Decrypt(eblof.priv, pair[0].Bytes())
		if e != nil {
			log.Fatalln(e)
		}
		m1, e := paillier.Decrypt(eblof.priv, pair[1].Bytes())
		if e != nil {
			log.Fatalln(e)
		}

		if new(big.Int).SetBytes(m0).Cmp(big.NewInt(0)) != 0 {
			log.Fatalln("Should be encryption of zero [0]")
		}
		if new(big.Int).SetBytes(m1).Cmp(big.NewInt(0)) != 0 {
			log.Fatalln("Should be encryption of zero [1]")
		}
	}

	// Check can recover element that does not exist
	r, e := rand.Int(rand.Reader, big.NewInt(max))
	if e != nil {
		log.Fatalln(e)
	}
	key := r.Bytes()

	eblof.ca = [][]*big.Int{}
	eblof.tmpCa = map[string][]*big.Int{}
	eblof.Check(key)
	eblof.HomCombine()
	pair := eblof.ca[0]

	m0, e := paillier.Decrypt(eblof.priv, pair[0].Bytes())
	if e != nil {
		log.Fatalln(e)
	}
	m1, e := paillier.Decrypt(eblof.priv, pair[1].Bytes())
	if e != nil {
		log.Fatalln(e)
	}

	cinv := new(big.Int).ModInverse(new(big.Int).SetBytes(m1), eblof.pub.N)
	if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).SetBytes(m0), cinv), eblof.pub.N).Cmp(r) != 0 {
		log.Fatalln("Failed to recover union element")
	}
}

func interTest(keys []*big.Int, eblof *EncBloom) {
	for _, v := range keys {
		eblof.Check(v.Bytes())
	}
	eblof.HomCombine()

	for i := range eblof.ca {
		pair := eblof.ca[i]

		m0, e := paillier.Decrypt(eblof.priv, pair[0].Bytes())
		if e != nil {
			log.Fatalln(e)
		}
		m1, e := paillier.Decrypt(eblof.priv, pair[1].Bytes())
		if e != nil {
			log.Fatalln(e)
		}

		b := false
		for j := range keys {
			if new(big.Int).SetBytes(m0).Cmp(keys[j]) == 0 {
				b = true
			}
		}

		if !b {
			log.Println(new(big.Int).SetBytes(m0))
			log.Println(keys[i])
			log.Fatalln("Should be encryption of original element [0]")
		}
		if new(big.Int).SetBytes(m1).Cmp(big.NewInt(0)) != 0 {
			log.Fatalln("Should be encryption of zero [1]")
		}
	}

	r, e := rand.Int(rand.Reader, big.NewInt(max))
	if e != nil {
		log.Fatalln(e)
	}
	key := r.Bytes()

	eblof.ca = [][]*big.Int{}
	eblof.tmpCa = map[string][]*big.Int{}
	eblof.Check(key)
	eblof.HomCombine()
	pair := eblof.ca[0]

	m1, e := paillier.Decrypt(eblof.priv, pair[1].Bytes())
	if e != nil {
		log.Fatalln(e)
	}

	if new(big.Int).SetBytes(m1).Cmp(big.NewInt(0)) == 0 {
		log.Fatalln("Shouldn't be encryption of zero [int]")
	}
}

func caTest(keys []*big.Int, eblof *EncBloom) {
	for _, v := range keys {
		eblof.Check(v.Bytes())
	}
	eblof.HomCombine()

	for i := range eblof.ca {
		out := eblof.ca[i]

		m, e := paillier.Decrypt(eblof.priv, out[0].Bytes())
		if e != nil {
			log.Fatalln(e)
		}

		if new(big.Int).SetBytes(m).Cmp(big.NewInt(0)) != 0 {
			log.Fatalln("Should be encryption of zero [1]")
		}
	}

	r, e := rand.Int(rand.Reader, big.NewInt(max))
	if e != nil {
		log.Fatalln(e)
	}
	key := r.Bytes()

	eblof.ca = [][]*big.Int{}
	eblof.tmpCa = map[string][]*big.Int{}
	eblof.Check(key)
	eblof.HomCombine()
	out := eblof.ca[0]

	m, e := paillier.Decrypt(eblof.priv, out[0].Bytes())
	if e != nil {
		log.Fatalln(e)
	}

	if new(big.Int).SetBytes(m).Cmp(big.NewInt(0)) == 0 {
		log.Fatalln("Shouldn't be encryption of zero [car]")
	}
}
