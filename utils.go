package fancaster_anonymous_circuit

import (
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/sha3"
	"math/big"
)

func ComputeEthereumAddress(pubKey *ecdsa.PublicKey) []byte {
	pubKeyBytes := pubKey.Bytes()
	pubKeyBytes = pubKeyBytes[:]

	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyBytes)
	hashed := hash.Sum(nil)
	address := hashed[12:]

	return address
}

func BigEndianBytesToVar(api frontend.API, data []frontend.Variable) frontend.Variable {
	x := frontend.Variable(0)

	for i := 0; i < 20; i++ {
		x = api.Mul(x, frontend.Variable(256))
		x = api.Add(x, data[i])
	}
	return x
}

func privateKeyToHex(priv *ecdsa.PrivateKey) string {
	hexStr := priv.Bytes()[64:]
	addr := fmt.Sprintf("%x", hexStr)
	return addr
}

func isValidEthereumPrivateKey(hexKey string) bool {
	if len(hexKey) != 64 {
		return false
	}

	privBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return false
	}
	privKey := new(big.Int).SetBytes(privBytes)

	n := secp256k1.S256().N
	if privKey.Cmp(big.NewInt(1)) < 0 || privKey.Cmp(n) >= 0 {
		return false
	}

	return true
}
