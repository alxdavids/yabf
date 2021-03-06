package encbf

import (
	"crypto/rand"
	"encoding/binary"
	"github.com/alxdavids/bloom-filter"
	"github.com/alxdavids/bloom-filter/standard"
	"github.com/mcornejo/go-go-gadget-paillier"
	"github.com/reusee/mmh3"
	"hash"
	"log"
	"math/big"
	"sync"
	"time"
	"xojoc.pw/bitset"
)

type EncBloom struct {
	h     hash.Hash               // hash function used for query and storage
	L     uint                    // Length of Bloom filter
	k     uint                    // Number of hash functions
	eps   float64                 // false-positive probability
	n     uint                    // predicted size of set
	ebf   []*big.Int              // complete array of encrypted bits
	bf    *bitset.BitSet          // original bits (for testing)
	bs    []uint                  // array of k bits from hash functions
	m     uint                    // size of second set
	ca    [][]*big.Int            // array of combined ciphertexts
	tmpCa map[string]([]*big.Int) // temp array for holding ciphertexts for combining
	pub   *paillier.PublicKey     // public key for encryption
	priv  *paillier.PrivateKey    // private key for decryption
	mode  int                     // mode for performing PSO (0 = PSU, 1 = PSI, 2 = PSI/PSU-CA)
}

var _ bloom.Bloom = (*EncBloom)(nil)

func New(sbf *standard.StandardBloom, keySize, mode, maxConcurrentGoroutines int) bloom.Bloom {
	h, L, k, n, eps, sbfa := sbf.GetParams()

	keyTime := time.Now()
	priv, e := paillier.GenerateKey(rand.Reader, keySize)
	if e != nil {
		log.Fatalln(e)
	}
	pub := &priv.PublicKey
	log.Printf("Key time: %v", time.Since(keyTime).Seconds())

	// construct ciphertexts for bloom filter
	ebf := make([]*big.Int, uint(L))

	// Use this channel for limiting goroutines
	concurrentGoroutines := make(chan struct{}, maxConcurrentGoroutines)
	for i := 0; i < maxConcurrentGoroutines; i++ {
		concurrentGoroutines <- struct{}{}
	}
	done := make(chan bool)
	waitForAllJobs := make(chan bool)

	// Collect all the jobs, and since the job is finished, we can
	// release another spot for a goroutine.
	go func() {
		for i := uint(0); i < L; i++ {
			<-done
			// Say that another goroutine can now start.
			concurrentGoroutines <- struct{}{}
		}
		// We have collected all the jobs, the program
		// can now terminate
		waitForAllJobs <- true
	}()

	// Start the encryption process with limited goroutines
	encTime := time.Now()
	for i := uint(0); i < L; i++ {
		// Wait till we're allowed to go
		<-concurrentGoroutines

		go func(i uint, ebf []*big.Int, sbfa *bitset.BitSet) {
			var m *big.Int
			// Remember that we operate over an encrypted Bloom filter
			if sbfa.Get(int(i)) {
				m = big.NewInt(0)
			} else {
				m = big.NewInt(1)
			}
			c, e := paillier.Encrypt(pub, m.Bytes())
			if e != nil {
				log.Fatalln(e)
			}

			cInt := new(big.Int).SetBytes(c)
			ebf[i] = cInt

			done <- true
		}(i, ebf, sbfa)
	}
	<-waitForAllJobs
	log.Printf("Enc time: %v", time.Since(encTime).Seconds())

	return &EncBloom{
		h:     h,
		k:     k,
		L:     L,
		eps:   eps,
		n:     n,
		ebf:   ebf,
		bf:    sbfa,
		bs:    make([]uint, uint(k)),
		m:     n,
		ca:    [][]*big.Int{},
		tmpCa: map[string][]*big.Int{},
		pub:   pub,
		priv:  priv,
		mode:  mode,
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
		combArr[i] = this.ebf[v]
	}

	this.tmpCa[string(key)] = combArr

	// var arr []*big.Int
	// if this.mode == 0 {
	// 	arr = this.compUnionPair(combArr, key)
	// } else if this.mode == 1 {
	// 	arr = this.compInterPair(combArr, key)
	// } else if this.mode == 2 {
	// 	arr = this.compCaPair(combArr)
	// }
	// this.ca = append(this.ca, arr)

	return true
}

// Homomorphically combine ciphertexts
func (this *EncBloom) HomCombine() {
	var wg sync.WaitGroup
	wg.Add(len(this.tmpCa))
	for key, v := range this.tmpCa {
		go func(key string, v []*big.Int) {
			defer wg.Done()
			var arr []*big.Int
			if this.mode == 0 {
				arr = this.compUnionPair(v, []byte(key))
			} else if this.mode == 1 {
				arr = this.compInterPair(v, []byte(key))
			} else if this.mode == 2 {
				arr = this.compCaPair(v)
			}
			this.ca = append(this.ca, arr)
		}(key, v)
	}
	wg.Wait()
}

func (this *EncBloom) Reset() {
	this.k = bloom.K(this.eps)
	this.L = bloom.L(this.eps, this.n)
	this.ebf = make([]*big.Int, this.L)
	this.bs = make([]uint, this.k)
	this.h = mmh3.New128()
	this.ca = [][]*big.Int{}
	this.tmpCa = map[string][]*big.Int{}
}

func (this *EncBloom) ResetForTesting() {
	this.ca = [][]*big.Int{}
	this.tmpCa = map[string][]*big.Int{}
}

// Decrypt method for use when interacting with EBF
func (this *EncBloom) Decrypt() [][][]byte {
	ptxts := make([][][]byte, len(this.ca))
	for i, v := range this.ca {
		m0, e := paillier.Decrypt(this.priv, v[0].Bytes())
		if e != nil {
			log.Fatalln(e)
		}

		var m1 []byte
		if len(v) > 1 {
			m1, e = paillier.Decrypt(this.priv, v[1].Bytes())
			if e != nil {
				log.Fatalln(e)
			}
		}

		ptxts[i] = [][]byte{m0, m1}
	}

	return ptxts
}

func (this *EncBloom) GetPubKey() *paillier.PublicKey {
	return this.pub
}

func (this *EncBloom) DumpParams() {
	log.Printf("L: %v,\n k: %v,\n eps: %v,\n n: %v,\n mode: %v,\n", this.L, this.k, this.eps, this.n, this.mode)
}

func (this *EncBloom) compUnionPair(combArr []*big.Int, key []byte) []*big.Int {
	var ciph []byte
	for i, _ := range combArr {
		if i == 0 {
			ciph = combArr[i].Bytes()
		}

		if i < len(combArr)-1 {
			ciph = paillier.AddCipher(this.pub, ciph, combArr[i+1].Bytes())
		}
	}
	ckey := paillier.Mul(this.pub, ciph, key)
	c00, e := paillier.Encrypt(this.pub, big.NewInt(0).Bytes())
	if e != nil {
		log.Fatalln(e)
	}
	c01, e := paillier.Encrypt(this.pub, big.NewInt(0).Bytes())
	if e != nil {
		log.Fatalln(e)
	}
	ckey = paillier.AddCipher(this.pub, ckey, c00)
	ciph = paillier.AddCipher(this.pub, ciph, c01)

	pair := []*big.Int{new(big.Int).SetBytes(ckey), new(big.Int).SetBytes(ciph)}
	return pair
}

func (this *EncBloom) compInterPair(combArr []*big.Int, key []byte) []*big.Int {
	var ciph []byte
	for i, _ := range combArr {
		if i == 0 {
			ciph = combArr[i].Bytes()
		}

		if i < len(combArr)-1 {
			ciph = paillier.AddCipher(this.pub, ciph, combArr[i+1].Bytes())
		}
	}
	r, e := rand.Int(rand.Reader, this.pub.N)
	if e != nil {
		log.Fatalln(e)
	}
	cr := paillier.Mul(this.pub, ciph, r.Bytes())
	ckey, e := paillier.Encrypt(this.pub, key)
	if e != nil {
		log.Fatalln(e)
	}
	ckey = paillier.AddCipher(this.pub, cr, ckey)

	pair := []*big.Int{new(big.Int).SetBytes(ckey), new(big.Int).SetBytes(ciph)}
	return pair
}

func (this *EncBloom) compCaPair(combArr []*big.Int) []*big.Int {
	var ciph []byte
	for i, _ := range combArr {
		if i == 0 {
			ciph = combArr[i].Bytes()
		}

		if i < len(combArr)-1 {
			ciph = paillier.AddCipher(this.pub, ciph, combArr[i+1].Bytes())
		}
	}
	r, e := rand.Int(rand.Reader, this.pub.N)
	if e != nil {
		log.Fatalln(e)
	}
	cr := paillier.Mul(this.pub, ciph, r.Bytes())

	out := []*big.Int{new(big.Int).SetBytes(cr)}
	return out
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
