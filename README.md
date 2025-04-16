# Fancaster Anonymous Circuit - Gnark version

## License
This project is licensed under a **Commercial Software License**.  
Unauthorized use, copying, distribution, or modification of this software is prohibited.  
For licensing inquiries, please contact https://t.me/zerobasezk.

## Overview
This repository contains a zero-knowledge circuit implementation for ECDSA signature verification and Merkle tree inclusion proof using the gnark framework.

The circuit performs the following operations:
- ECDSA signature recovery (ecrecover) on secp256k1
- Converts the recovered public key to an Ethereum address
- Verifies the address is included in a Merkle tree with the given root hash

## Circuit Structure
The Circuit struct contains the following inputs:
- Message: The signed message (hash) as a field element
- V, R, S: ECDSA signature components
- Expected: Expected recovered public key point (for verification)
- RootHash: Merkle tree root hash
- Index: Leaf index in the Merkle tree
- Path: Merkle proof path (14 elements)

## Environment
- Go: 1.23.0
- gnark: v0.12.1
- gnark-crypto: v0.16.1
- curve: BN254
- hasher: mimc

## Files
- hash.go: Keccak256
- merkle.go: Use mimc to verify merkle
- pub2addr.go: Convert public key to Ethereum address
- circuit.go: Gnark circuit
- utils.go: tools

## Performance Summary
- Total Constraints: 304061
- Proof Generation Time: ~500ms 