package fancaster_anonymous_circuit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark/constraint/solver"
)

func Pub2AddrHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 8 {
		return fmt.Errorf("expected 8 inputs, got %d", len(inputs))
	}

	var x fp.Element
	x.SetBigInt(inputs[0])
	for i := 1; i < 4; i++ {
		var z fp.Element
		limbs := new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil)
		z.SetBigInt(limbs)

		var a fp.Element
		a.SetBigInt(inputs[i])
		x.Mul(&x, &z).Add(&x, &a)
	}

	var y fp.Element
	y.SetBigInt(inputs[4])
	for i := 5; i < 8; i++ {
		var z fp.Element
		limbs := new(big.Int).Exp(big.NewInt(2), big.NewInt(64), nil)
		z.SetBigInt(limbs)

		var a fp.Element
		a.SetBigInt(inputs[i])
		y.Mul(&y, &z).Add(&y, &a)
	}

	pubBytes := make([]byte, 65)
	pubBytes[0] = 0x04
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(pubBytes[1:33], xBytes[:])
	copy(pubBytes[33:], yBytes[:])

	for i := 0; i < 64; i++ {
		outputs[i] = big.NewInt(int64(pubBytes[i+1]))
	}

	return nil
}

func init() {
	solver.RegisterHint(Pub2AddrHint)
}
