package main

import (
	"RSA/RSA"
	"errors"
)

func main() {
	r := RSA.NewRSACryptoSystem(10007, 10009)
	if r == nil {
		panic(errors.New("error creating a new RSA cryptography system"))
	}
	r.Encrypt(RSA.Message(5))
}
