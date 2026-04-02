# Key types for digital signatures (ML-DSA / SLH-DSA)

"""
    SigParams

Parameter set identifier for digital signatures. Use the constants
`ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87` (FIPS 204) or
`SLH_DSA_SHA2_128s`, `SLH_DSA_SHA2_192s`, `SLH_DSA_SHA2_256s` (FIPS 205).
"""
struct SigParams
    alg_name::String
end

# ML-DSA parameter sets (FIPS 204)
const ML_DSA_44 = SigParams(MLDSA44)
const ML_DSA_65 = SigParams(MLDSA65)
const ML_DSA_87 = SigParams(MLDSA87)

# SLH-DSA parameter sets (FIPS 205)
const SLH_DSA_SHA2_128s = SigParams(SLHDSA_SHA2_128s)
const SLH_DSA_SHA2_192s = SigParams(SLHDSA_SHA2_192s)
const SLH_DSA_SHA2_256s = SigParams(SLHDSA_SHA2_256s)

"""
    SigPublicKey

Public verification key. Safe to share.
"""
struct SigPublicKey
    params::SigParams
    data::Vector{UInt8}
end

"""
    SigPrivateKey

Private signing key. Stored in a SecureBuffer that is zeroed on GC.
"""
struct SigPrivateKey
    params::SigParams
    data::SecureBuffer
end

"""
    wipe!(key::SigPrivateKey)

Explicitly zero the private key material.
"""
wipe!(key::SigPrivateKey) = wipe!(key.data)

# Show methods — NEVER print key material
Base.show(io::IO, k::SigPublicKey) = print(io, "SigPublicKey($(k.params.alg_name), $(length(k.data)) bytes)")
Base.show(io::IO, k::SigPrivateKey) = print(io, "SigPrivateKey($(k.params.alg_name), $(length(k.data)) bytes)")
