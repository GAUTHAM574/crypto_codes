package main

import (
	"ecc/ecc"
	"fmt"
)

func main() {
	e, err := ecc.NewEllipticCurveCryptoSystem(10007, 1334, 643)
	if err != nil {
		fmt.Printf("Error creating a new elliptic curve cryptography system: %v\n", err)
		return
	}
	originalMessage := e.CreateMessage(2, 4)
	fmt.Printf("Original message: (%v, %v)\n", originalMessage.X, originalMessage.Y)
	decryptedMessage := e.DecryptBackDoor(e.Encrypt(originalMessage))
	fmt.Printf("Decrypted message: (%v, %v)", decryptedMessage.X, decryptedMessage.Y)
}
