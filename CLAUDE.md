# CLAUDE.md

## Project Overview
QuantumCrypto.jl provides post-quantum cryptography for Julia via liboqs.
Phase 1: ML-KEM + KEM-DEM. Phase 2: ML-DSA + SLH-DSA. Phase 3: Hybrid.

## Build and Test
```bash
julia --project -e 'using Pkg; Pkg.instantiate()'
julia --project -e 'using Pkg; Pkg.test()'
```

## Architecture
- All crypto ops happen in C (liboqs, OpenSSL). No pure Julia crypto.
- Private keys wrapped in SecureBuffer with zeroing finalizer.
- KEM-DEM pattern: ML-KEM encapsulation + AES-256-GCM symmetric encryption.

## Key Dependencies
- liboqs_jll: Post-quantum KEM algorithms (ML-KEM-512/768/1024)
- OpenSSL_jll: AES-256-GCM for KEM-DEM symmetric encryption
