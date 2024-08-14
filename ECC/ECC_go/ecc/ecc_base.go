package ecc

import "errors"

// Point have x and y co-ordinates of a point in ECC.
type Point struct {
	X, Y int64
}

// generator is used to generate other points in the cyclic sub group of the ECC.
type generator struct {
	X, Y int64
}

// privateKey is the private key of ECC system.
type privateKey int64

// publicKey is the public key of ECC system.
type PublicKey struct {
	X, Y int64
}

// Message is the message in the ECC system represented in x and y coordinates.
type Message struct {
	X, Y int64
}

// cryptPoint is the points in the crypted message in x and y coordinates.
type cryptPoint struct {
	x, y int64
}

// CryptedMessage is the encrypted message in the ECC system represented in x and y coordinates and has two parts.
type CryptedMessage struct {
	C1 *cryptPoint
	C2 *cryptPoint
}

// curveEquation has p, a, b parameters which are used to create the curve.
type curveEquation struct {
	p, a, b int64
}

// EllipticCurveCryptoI contains all the methods required for elliptic curve cryptography.
type EllipticCurveCryptoI interface {
	// To create curve
	IsSuitablePrime(p int64) bool
	setGenerator() error
	generateKeys()

	// Generic methods required for ECC
	extendedEuclidian(a, b, s1, s2 int64) int64
	mod(x int64) int64
	getRandom() int64
	expPower(base, exp int64) int64
	isQuadraticNonResiude(y int64) bool

	// Point arithmetic operations and related functions
	CreatePoint(x, y int64) *Point
	arePointsSame(p1, p2 *Point) bool
	isIdentityPoint(p1 *Point) bool
	getSlope(p1, p2 *Point) int64
	addPoints(p1, p2 *Point) *Point
	subPoints(p1, p2 *Point) *Point
	multiplyPoint(p1 *Point, scalar int64) *Point

	// Operations required for ECC
	CreateMessage(x, y int64) *Message
	Encrypt(*Message) *CryptedMessage
	decrypt(*CryptedMessage) *Message
	DecryptBackDoor(*CryptedMessage) *Message
}

// To create curve
func IsSuitablePrime(p int64) bool {
	panic(errors.New("not implemented"))
}

func setGenerator() error {
	panic(errors.New("not implemented"))
}

func generateKeys() {
	panic(errors.New("not implemented"))
}

// Generic methods required for ECC
func extendedEuclidian(a, b, s1, s2 int64) int64 {
	panic(errors.New("not implemented"))
}

func mod(x int64) int64 {
	panic(errors.New("not implemented"))
}

func getRandom() int64 {
	panic(errors.New("not implemented"))
}

func expPower(base, exp int64) int64 {
	panic(errors.New("not implemented"))
}

func isQuadraticNonResiude(y int64) bool {
	panic(errors.New("not implemented"))
}

func CreatePoint(x, y int64) *Point {
	panic(errors.New("not implemented"))
}

func arePointsSame(p1, p2 *Point) bool {
	panic(errors.New("not implemented"))
}

func isIdentityPoint(p1 *Point) bool {
	panic(errors.New("not implemented"))
}

func getSlope(p1, p2 *Point) int64 {
	panic(errors.New("not implemented"))
}

func addPoints(p1, p2 *Point) *Point {
	panic(errors.New("not implemented"))
}

func subPoints(p1, p2 *Point) *Point {
	panic(errors.New("not implemented"))
}

func multiplyPoint(p1 *Point, scalar int64) *Point {
	panic(errors.New("not implemented"))
}

// Operations required for ECC
func CreateMessage(x, y int64) *Message {
	panic(errors.New("not implemented"))
}

func Encrypt(msg *Message) *CryptedMessage {
	panic(errors.New("not implemented"))
}

func decrypt(cryptedMsg *CryptedMessage) *Message {
	panic(errors.New("not implemented"))
}

func DecryptBackDoor(cryptedMsg *CryptedMessage) *Message {
	panic(errors.New("not implemented"))
}
