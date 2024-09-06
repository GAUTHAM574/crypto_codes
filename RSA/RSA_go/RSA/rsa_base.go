package RSA

import "errors"

//Data structure required for the RSA algorithm.

// privateKey contains two primes p, q and the d which is the inverse of the public key.
type privateKey struct {
	p   int64
	q   int64
	phi int64 // (p-1)(q-1)
	d   int64
}

// public key contains n and e, a random number.
type PublicKey struct {
	n int64
	e int64
}

// message is a integer value given by the users.
type Message int64

// cipheredMessage contains the encrypted message.
type cipheredMessage int64

type RSACryptoSystemI interface {
	getRandom() int64
	getRandomPrime() int64
	mod(i int64, base *int64) int64
	pow(base, exp int64) int64
	extendedEuclidean(r1, r2, s1, s2 int64) (bool, int64)
	getValueAndMultiplicativeInverse() (int64, int64)
	keyGeneration()
	decrypt(C *cipheredMessage) *Message
	IsPrime(x int64) bool
	Encrypt(M *Message) *cipheredMessage
	DecryptBackdoor(C cipheredMessage) *Message
}

func getRandom() int64 {
	panic(errors.New("not implemented"))
}

func getRandomPrime() int64 {
	panic(errors.New("not implemented"))
}

func mod(i, base int64) int64 {
	panic(errors.New("not implemented"))
}

func pow(base, exp int64) int64 {
	panic(errors.New("not implemented"))
}

func extendedEuclidean(r1, r2, s1, s2 int64) (bool, int64) {
	panic(errors.New("not implemented"))
}

func getValueAndMultiplicativeInverse() (int64, int64) {
	panic(errors.New("not implemented"))
}

func keyGeneration() {
	panic(errors.New("not implemented"))
}

func decrypt(C *cipheredMessage) Message {
	panic(errors.New("not implemented"))
}

func IsPrime(x int64) bool {
	panic(errors.New("not implemented"))
}

func Encrypt(M Message) cipheredMessage {
	panic(errors.New("not implemented"))
}

func DecryptBackdoor(C cipheredMessage) Message {
	panic(errors.New("not implemented"))
}
