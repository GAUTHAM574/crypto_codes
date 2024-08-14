package ecc

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
)

var _ = new(EllipticCurveCryptoSystem)

type EllipticCurveCryptoSystem struct {
	*curveEquation
	*generator
	privateKey
	*PublicKey
	EllipticCurveCryptoI
}

// IsSuitablePrime check if p satisfies the condition.
func (*EllipticCurveCryptoSystem) IsSuitablePrime(p int64) bool {
	if p%4 != 3 || p%2 == 0 || p < 0 {
		return false
	}
	sqrtP := int64(math.Sqrt(float64(p)))
	for i := int64(2); i <= sqrtP; i++ {
		if p%i == 0 {
			return false
		}
	}
	return true
}

// mod return the mod value of a number in the field of prime p.
func (e *EllipticCurveCryptoSystem) mod(x int64) int64 {
	if x >= 0 {
		return x % e.p
	}
	var q int64 = int64((-x)/e.p) + 1
	return (x + q*e.p) % e.p
}

// extendedEuclidean returns the inverse of a value in the field of prime p.
func (e *EllipticCurveCryptoSystem) extendedEuclidian(a, b, s1, s2 int64) int64 {
	if b == 1 {
		return e.mod(s2)
	}
	if b > a {
		t := a
		a = b
		b = t
	}
	q := e.mod(a / b)
	r := e.mod(a % b)
	return e.extendedEuclidian(b, r, e.mod(s2), e.mod(s1-(q*s2)))
}

// getRandom returns a random integer in field of p
func (e *EllipticCurveCryptoSystem) getRandom() int64 {
	randomInt64 := int64(0)
	for randomInt64 == 0 {
		randomInt64 = (int64(rand.Int63n(e.p)) << 1) | int64(rand.Intn(2))
	}
	return e.mod(randomInt64)
}

// expPower raises a nase to a exponent power and return it mod value.
func (e *EllipticCurveCryptoSystem) expPower(base, exponent int64) int64 {
	if exponent == 0 {
		return 1
	}
	exponent = exponent % (e.p - 1) // fermet's little theorem pow(a, p-1) mod p == 1 mod p
	var expBinary strings.Builder
	for exponent > 0 {
		expBinary.WriteString(fmt.Sprintf("%v", (exponent%2)&1))
		exponent = exponent >> 1
	}
	expBinaryStr := expBinary.String()
	len := expBinary.Len()
	binaryPowers := make([]int64, len)
	binaryPowers[0] = e.mod(base)
	res := int64(1)
	if expBinaryStr[0] == '1' {
		res = base
	}
	for i := 1; i < len; i++ {
		binaryPowers[i] = e.mod(binaryPowers[i-1] * binaryPowers[i-1])
		if expBinaryStr[i] == '1' {
			res = e.mod(res * binaryPowers[i])
		}
	}
	return res
}

func (e *EllipticCurveCryptoSystem) CreatePoint(x, y int64) *Point {
	point := new(Point)
	point.X = x
	point.Y = y
	return point
}

func (e *EllipticCurveCryptoSystem) arePointsSame(p1, p2 *Point) bool {
	if p1.X != p2.X {
		return false
	}
	return p1.Y == p2.Y
}

func (e *EllipticCurveCryptoSystem) isIdentityPoint(p1 *Point) bool {
	return p1.X == -1 && p1.Y == -1
}

// getSlope returns the slope of the curve between two points.
func (e *EllipticCurveCryptoSystem) getSlope(p1, p2 *Point) int64 {
	if e.arePointsSame(p1, p2) {
		num := e.mod(e.mod(3*p1.X*p1.X) + e.a)
		denom := e.mod(p1.Y + p1.Y)
		return e.mod(num * e.extendedEuclidian(e.p, denom, 0, 1))
	}
	num := e.mod(p2.Y - p1.Y)
	denom := e.extendedEuclidian(e.p, e.mod(p2.X-p1.X), 0, 1)
	return e.mod(num * denom)
}

// addPoint adds two points in the elliptic curve.
func (e *EllipticCurveCryptoSystem) addPoints(p1, p2 *Point) *Point {
	if e.isIdentityPoint(p2) { // p2 is identity
		return e.CreatePoint(p1.X, p1.Y)
	} else if e.isIdentityPoint(p1) { // p1 is identity
		return e.CreatePoint(p2.X, p2.Y)
	}
	if e.arePointsSame(p1, e.CreatePoint(p2.X, e.mod(-p2.Y))) { // p2 is additive inverse of p1
		return e.CreatePoint(-1, -1) // creating identity point
	}
	slope := e.getSlope(p1, p2)
	x3 := e.mod(slope*slope - p1.X - p2.X)
	y3 := e.mod(slope*(p1.X-x3) - p1.Y)
	return e.CreatePoint(x3, y3)
}

// subPoints subtracts two points in the Elliptic curve.
func (e *EllipticCurveCryptoSystem) subPoints(p1, p2 *Point) *Point {
	if e.isIdentityPoint(p2) {
		return e.CreatePoint(p1.X, p1.Y)
	}
	t := e.CreatePoint(p2.X, e.mod(-p2.Y))
	res := e.addPoints(p1, t)
	return res
}

// multiplyPoint multiplies a point in the Elliptic curve with a scalar.
func (e *EllipticCurveCryptoSystem) multiplyPoint(p1 *Point, scalar int64) *Point {
	var t *Point //temp point
	if scalar <= 0 {
		panic("Cannot multiply point with negative value")
	} else if scalar == 1 || e.isIdentityPoint(p1) {
		return e.CreatePoint(p1.X, p1.Y)
	}
	t = e.addPoints(p1, p1)
	for i := int64(3); i <= scalar; i++ {
		t = e.addPoints(t, p1)
	}
	return t
}

// isQuadraticNonResiude checks if the given value of y has solution.
func (e *EllipticCurveCryptoSystem) isQuadraticNonResiude(y int64) bool {
	exp := (e.p - 1) / 2
	return e.mod(e.expPower(y, exp)) == 1
}

// setGenerator sets the generator.
func (e *EllipticCurveCryptoSystem) setGenerator() error {
	var cyclicSubGroup []*Point
	exp := (e.p + 1) / 4
	for i := int64(1); i < e.p; i++ {
		y2 := i*i*i + e.a*i + e.b
		if e.isQuadraticNonResiude(y2) {
			p1 := e.CreatePoint(e.mod(i), e.expPower(y2, exp))
			p2 := e.CreatePoint(p1.X, e.mod(-p1.Y))
			cyclicSubGroup = append(cyclicSubGroup, p1, p2)
		}
	}
	len := int64(len(cyclicSubGroup))
	if len == 0 {
		return fmt.Errorf("no points in Elliptic Curve to set as generator")
	}

	randInd := (e.getRandom() * e.getRandom()) % len
	e.generator = (*generator)(cyclicSubGroup[randInd])
	return nil
}

// generateKey generates the public key and private key.
func (e *EllipticCurveCryptoSystem) generateKeys() {
	e.privateKey = privateKey(e.getRandom())
	t := e.multiplyPoint((*Point)(e.generator), int64(e.privateKey))
	e.PublicKey = (*PublicKey)(t)
}

// createMessage creates a message pointer and set it's x and y value.
func (e *EllipticCurveCryptoSystem) CreateMessage(x, y int64) *Message {
	m := new(Message)
	m.X = e.mod(x)
	m.Y = e.mod(y)
	return m
}

// Encrypt encrypts a message into a cryptographically secure message.
func (e *EllipticCurveCryptoSystem) Encrypt(m *Message) *CryptedMessage {
	C := new(CryptedMessage)
	C.C1 = new(cryptPoint)
	C.C2 = new(cryptPoint)
	k := e.getRandom()

	t1 := e.multiplyPoint((*Point)(e.generator), k)
	C.C1.x = t1.X
	C.C1.y = t1.Y

	t2 := e.multiplyPoint((*Point)(e.PublicKey), k)
	t3 := e.addPoints((*Point)(m), t2)
	C.C2.x = t3.X
	C.C2.y = t3.Y

	fmt.Printf("Random K: %v\n", k)
	fmt.Printf("Crypted Message:\nC1: (%v, %v)\nC2: (%v, %v)\n", C.C1.x, C.C1.y, C.C2.x, C.C2.y)
	return C
}

func (e *EllipticCurveCryptoSystem) decrypt(C *CryptedMessage) *Message {

	c1 := new(Point)
	c1.X = C.C1.x
	c1.Y = C.C1.y
	t := e.multiplyPoint(c1, int64(e.privateKey))
	c2 := new(Point)
	c2.X = C.C2.x
	c2.Y = C.C2.y
	return (*Message)(e.subPoints(c2, t))
}

func (e *EllipticCurveCryptoSystem) DecryptBackDoor(C *CryptedMessage) *Message {
	return e.decrypt(C)
}

func NewEllipticCurveCryptoSystem(p, a, b int64) (*EllipticCurveCryptoSystem, error) {
	eccSys := new(EllipticCurveCryptoSystem)
	var EllipticCurveCryptoInstance EllipticCurveCryptoI
	eccSys.EllipticCurveCryptoI = EllipticCurveCryptoInstance
	curveEq := new(curveEquation)
	if !eccSys.IsSuitablePrime(p) {
		return nil, fmt.Errorf("p must be a prime number of format 4n+3")
	}
	curveEq.p = p
	curveEq.a = a
	curveEq.b = b
	eccSys.curveEquation = curveEq

	err := eccSys.setGenerator()
	if err != nil {
		return nil, err
	}
	eccSys.generateKeys()

	fmt.Printf("Generator: (%v, %v)\n", eccSys.generator.X, eccSys.generator.Y)
	fmt.Printf("PrivateKey: %v\n", eccSys.privateKey)
	fmt.Printf("PublicKey: (%v, %v)\n", eccSys.PublicKey.X, eccSys.PublicKey.Y)
	return eccSys, nil
}
