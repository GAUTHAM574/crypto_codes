package RSA

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
)

var _ = new(RSACryptoSystem)

const int64Max int64 = 9223372036854775807
const sqrtInt64Max int64 = 3037000499

type RSACryptoSystem struct {
	*privateKey
	*PublicKey
	RSACryptoSystemI
}

func (r *RSACryptoSystem) getRandom() int64 {
	randomInt64 := int64(0)
	for randomInt64 == 0 {
		randomInt64 = (int64(rand.Int63n(sqrtInt64Max)) << 1) | int64(rand.Intn(2))
	}
	return randomInt64
}

func (r *RSACryptoSystem) IsPrime(x int64) bool {
	sqrtX := int64(math.Sqrt(float64(x)))
	for i := int64(2); i <= sqrtX; i += 2 {
		if x%i == 0 {
			return false
		}
	}
	return true
}

func (r *RSACryptoSystem) getRandomPrime() int64 {
	rand1 := r.getRandom()
	if rand1%2 == 0 {
		rand1--
	}
	rand2 := rand1
	for rand1 < int64Max {
		if r.IsPrime(rand1) {
			return rand1
		} else if r.IsPrime(rand2) {
			return rand2
		}
		rand1++
		rand2--
	}
	panic(errors.New("cannot generate random prime"))
}

func (r *RSACryptoSystem) mod(i, base int64) int64 {
	if i >= 0 {
		return i % base
	}
	return (i % base) + base
}

func (r *RSACryptoSystem) pow(base, exp int64) int64 {
	var res int64 = 1
	for exp > 0 {
		if exp%2 == 1 {
			res = r.mod(res*base, r.PublicKey.n)
		}
		base = r.mod(base*base, r.PublicKey.n)
		exp /= 2
	}
	return r.mod(res, r.PublicKey.n)
}

func (r *RSACryptoSystem) extendedEuclidean(r1, r2, s1, s2 int64) (bool, int64) {
	if r2 == 1 {
		return true, r.mod(s2, r.privateKey.phi)
	}
	reminder := r1 % r2
	quotient := int64(r1 / r2)
	if reminder == 0 {
		return false, 0
	}
	return r.extendedEuclidean(r2, reminder, s2, s1-(s2*quotient))
}

func (r *RSACryptoSystem) getValueAndMultiplicativeInverse() (int64, int64) {
	var arr [][]int64
	for i := int64(3); i < r.privateKey.phi; i += 1 {
		if inverseExists, muliplicativeInverse := r.extendedEuclidean(r.phi, i, 0, 1); inverseExists {
			var t []int64
			t = append(t, i, muliplicativeInverse)
			arr = append(arr, t)
		}
	}
	len := len(arr)
	if len == 0 {
		panic(errors.New("error generating a value and a multiplicative inverse"))
	}
	randInd := r.mod((r.getRandom() * r.getRandom()), int64(len))
	println(randInd)
	return arr[randInd][0], arr[randInd][1]
}

func (r *RSACryptoSystem) keyGeneration() {
	r.PublicKey = new(PublicKey)
	r.PublicKey.n = int64(r.privateKey.p * r.privateKey.q)
	r.PublicKey.e, r.privateKey.d = r.getValueAndMultiplicativeInverse()
}

func (r *RSACryptoSystem) Encrypt(M Message) cipheredMessage {
	C := cipheredMessage(r.pow(int64(M), r.PublicKey.e))
	m := r.decrypt(C)

	fmt.Printf("Message: %v\n", M)
	fmt.Printf("Encrypted: %v\n", C)
	fmt.Printf("Decrypted: %v\n", m)
	return C
}

func (r *RSACryptoSystem) decrypt(C cipheredMessage) Message {
	return Message(r.pow(int64(C), r.privateKey.d))
}

func (r *RSACryptoSystem) DecryptBackdoor(C cipheredMessage) Message {
	return r.decrypt(C)
}

func NewRSACryptoSystemWithoutPrimeValues() *RSACryptoSystem {
	rsaSys := new(RSACryptoSystem)
	var RSACryptoSystemInstance RSACryptoSystemI
	rsaSys.RSACryptoSystemI = RSACryptoSystemInstance
	rsaSys.privateKey = new(privateKey)

	rsaSys.privateKey.p = rsaSys.getRandomPrime()
	rsaSys.privateKey.q = rsaSys.getRandomPrime()
	rsaSys.privateKey.phi = (rsaSys.privateKey.p - 1) * (rsaSys.privateKey.q - 1)
	rsaSys.keyGeneration()

	return rsaSys
}

func NewRSACryptoSystemWithPrimeValues(p, q int64) *RSACryptoSystem {
	rsaSys := new(RSACryptoSystem)
	var RSACryptoSystemInstance RSACryptoSystemI
	rsaSys.RSACryptoSystemI = RSACryptoSystemInstance
	rsaSys.privateKey = new(privateKey)

	rsaSys.privateKey.p = p
	rsaSys.privateKey.q = q
	rsaSys.privateKey.phi = (rsaSys.privateKey.p - 1) * (rsaSys.privateKey.q - 1)
	rsaSys.keyGeneration()

	fmt.Printf("Public Key: (n: %v, e:%v)\n", rsaSys.PublicKey.n, rsaSys.PublicKey.e)
	fmt.Printf("Private Key: (p: %v, q:%v, phi:%v, d:%v)\n", rsaSys.privateKey.p, rsaSys.privateKey.q, rsaSys.privateKey.phi, rsaSys.privateKey.d)
	return rsaSys
}

func NewRSACryptoSystem(primes ...int64) *RSACryptoSystem {
	if len(primes) == 0 {
		return NewRSACryptoSystemWithoutPrimeValues()
	} else if len(primes) == 2 {
		return NewRSACryptoSystemWithPrimeValues(primes[0], primes[1])
	}
	return nil
}
