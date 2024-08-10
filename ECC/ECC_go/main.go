package main

import (
	"ecc/ecc"
	"fmt"
)

func main() {
	fmt.Println("Hello World")
	fmt.Println(ecc.NewCurve(9, 0, 8))
}
