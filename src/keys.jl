# Key types for ML-KEM

"""
    MLKEMParams

Parameter set identifier for ML-KEM. Use the constants `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024`.
"""
struct MLKEMParams
    alg_name::String
end

# User-facing parameter set constants
const ML_KEM_512  = MLKEMParams(MLKEM512)
const ML_KEM_768  = MLKEMParams(MLKEM768)
const ML_KEM_1024 = MLKEMParams(MLKEM1024)

"""
    MLKEMPublicKey

Public key for ML-KEM. Safe to share.
"""
struct MLKEMPublicKey
    params::MLKEMParams
    data::Vector{UInt8}
end

"""
    MLKEMPrivateKey

Private key for ML-KEM. Stored in a SecureBuffer that is zeroed on GC.
"""
struct MLKEMPrivateKey
    params::MLKEMParams
    data::SecureBuffer
end

"""
    wipe!(key::MLKEMPrivateKey)

Explicitly zero the private key material.
"""
wipe!(key::MLKEMPrivateKey) = wipe!(key.data)

# Show methods — NEVER print key material
Base.show(io::IO, k::MLKEMPublicKey) = print(io, "MLKEMPublicKey($(k.params.alg_name), $(length(k.data)) bytes)")
Base.show(io::IO, k::MLKEMPrivateKey) = print(io, "MLKEMPrivateKey($(k.params.alg_name), $(length(k.data)) bytes)")
