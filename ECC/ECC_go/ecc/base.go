package ecc

import (
	"errors"
)

// Keys should be points
var Keys struct {
	PublicKey  *point
	privateKey *point
}

// point should have x and y co-ordinates
type point struct {
	x int64
	y int64
}

var Generator *point

type curve interface {
	generateCurve()
	encrypt()
	decrypt()
	addPoints()
}
type Curve struct {
	p, a, b int64
}

func (c Curve) generateCurve() any {
	return errors.New("not implemented")
}

func (c Curve) encrypt() any {
	return errors.New("not implemented")
}

func (c Curve) decrypt() any {
	return errors.New("not implemented")
}

func (c Curve) addPoints() any {
	return errors.New("not implemented")
}

func NewCurve(p, a, b int64) *Curve {
	return &Curve{p, a, b}
}
