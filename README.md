# QuantumCrypto.jl

Post-quantum cryptography for Julia, wrapping [liboqs](https://github.com/open-quantum-safe/liboqs).

## Status

Phase 1: ML-KEM key encapsulation + KEM-DEM asymmetric encryption.

## Installation

```julia
using Pkg
Pkg.add("QuantumCrypto")
```

## Quick Start

```julia
using QuantumCrypto

# Key generation
pub, priv = keygen(MLKEM768)

# Asymmetric encryption (KEM-DEM: ML-KEM + AES-256-GCM)
ciphertext = encrypt(pub, b"secret message")
plaintext = decrypt(priv, ciphertext)

# Raw key encapsulation
shared_secret, encapsulation = encapsulate(pub)
shared_secret2 = decapsulate(priv, encapsulation)
```
