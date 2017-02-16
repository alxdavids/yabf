package standard

import (
	"encoding/binary"
	"github.com/alxdavids/bloom-filter"
	"github.com/reusee/mmh3"
	"hash"
	"log"
	"xojoc.pw/bitset"
)

type StandardBloom struct {
	h   hash.Hash      // hash function used for query and storage
	L   uint           // Length of Bloom filter
	k   uint           // Number of hash functions
	eps float64        // false-positive probability
	n   uint           // predicted size of set
	bf  *bitset.BitSet // complete array of bits
	bs  []uint         // array of k bits from hash functions
	c   uint           // count of elements in the Bloom filter
}

var _ bloom.Bloom = (*StandardBloom)(nil)

func New(n uint, eps float64) bloom.Bloom {
	var (
		k = bloom.K(eps)
		L = bloom.L(eps, n)
		c = uint(0)
	)

	return &StandardBloom{
		h:   mmh3.New128(),
		k:   k,
		L:   L,
		eps: eps,
		n:   n,
		bf:  &bitset.BitSet{},
		bs:  make([]uint, uint(k)),
		c:   c,
	}
}

func (this *StandardBloom) SetHasher(h hash.Hash) {
	this.h = h
}

func (this *StandardBloom) Add(key []byte) bloom.Bloom {
	this.setBitset(key)
	for _, v := range this.bs[:this.k] {
		this.bf.Set(int(v))
	}

	this.c++
	if this.c > this.n {
		log.Println("Adding a greater number of elements than are expected. Expect failure.")
	}

	return this
}

func (this *StandardBloom) Check(key []byte) bool {
	this.setBitset(key)
	for _, v := range this.bs[:this.k] {
		if !this.bf.Get(int(v)) {
			return false
		}
	}

	return true
}

func (this *StandardBloom) Reset() {
	this.k = bloom.K(this.eps)
	this.L = bloom.L(this.eps, this.n)
	this.bf = &bitset.BitSet{}
	this.bs = make([]uint, this.k)
	this.c = 0
	this.h = mmh3.New128()
}

func (this *StandardBloom) GetParams() (hash.Hash, uint, uint, uint, float64, *bitset.BitSet) {
	return this.h, this.L, this.k, this.n, this.eps, this.bf
}

func (this *StandardBloom) setBitset(key []byte) {
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
