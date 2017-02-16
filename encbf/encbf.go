package enc

import (
	"encoding/binary"
	"github.com/alxdavids/bloom-filter"
	"github.com/alxdavids/bloom-filter/standard"
	"github.com/reusee/mmh3"
	"hash"
	"log"
	"math/big"
)

type EncBloom struct {
	h   hash.Hash  // hash function used for query and storage
	L   uint       // Length of Bloom filter
	k   uint       // Number of hash functions
	eps float64    // false-positive probability
	n   uint       // predicted size of set
	bf  []*big.Int // complete array of bits
	bs  []uint     // array of k bits from hash functions
	m   uint       // size of second set
	ca  []*big.Int // array of combined ciphertexts
}

var _ bloom.Bloom = (*EncBloom)(nil)

func New(sbf *standard.StandardBloom) bloom.Bloom {
	h, L, k, n, eps, sbfa := sbf.GetParams()

	bf := make([]*big.Int, uint(L))
	for i := uint(0); i < L; i++ {
		if sbfa.Get(int(i)) {
			// Encrypt the value 1
		} else {
			// Encrypt the value 0
		}
	}

	return &EncBloom{
		h:   h,
		k:   k,
		L:   L,
		eps: eps,
		n:   n,
		bf:  bf,
		bs:  make([]uint, uint(k)),
		m:   n,
		ca:  make([]*big.Int, uint(L)),
	}
}

func (this *EncBloom) SetHasher(h hash.Hash) {
	this.h = h
}

func (this *EncBloom) Add(key []byte) bloom.Bloom {
	log.Println("Adding elements in the encrypted setting is not permitted. No changes have been made.")
	return this
}

// This function is much different to the one in Standard Bloom
// We also populate an array of ciphertexts
func (this *EncBloom) Check(key []byte) bool {
	this.setBitset(key)
	combArr := make([]*big.Int, this.k)
	for i, v := range this.bs[:this.k] {
		c := this.bf[v]
		combArr[i] = c
	}

	// Homomorphically combine ciphertexts

	return true
}

func (this *EncBloom) Reset() {
	this.k = bloom.K(this.eps)
	this.L = bloom.L(this.eps, this.n)
	this.bf = make([]*big.Int, this.L)
	this.bs = make([]uint, this.k)
	this.h = mmh3.New128()
	this.ca = make([]*big.Int, this.L)
}

func (this *EncBloom) setBitset(key []byte) {
	this.h.Reset()
	h := this.h
	_, e := h.Write(key)
	if e != nil {
		log.Println(e)
	}
	s := h.Sum(nil)
	// Reference: Less Hashing, Same Performance: Building a Better Bloom Filter
	// URL: http://www.eecs.harvard.edu/~kirsch/pubs/bbbf/rsa.pdf
	s1 := binary.BigEndian.Uint32(s[0:4])
	s2 := binary.BigEndian.Uint32(s[4:8])

	for i, _ := range this.bs[:this.k] {
		this.bs[i] = (uint(s1) + uint(i)*uint(s2)) % this.L
	}
}
