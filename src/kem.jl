# High-level KEM operations wrapping the low-level liboqs API

"""
    keygen(params::MLKEMParams) -> (MLKEMPublicKey, MLKEMPrivateKey)

Generate a fresh ML-KEM keypair. The private key is stored in secure memory.

# Example
```julia
pub, priv = keygen(ML_KEM_768)
```
"""
function keygen(params::MLKEMParams)
    ctx = kem_new(params.alg_name)
    try
        pk_raw, sk_raw = kem_keypair(ctx)
        pub = MLKEMPublicKey(params, pk_raw)
        priv = MLKEMPrivateKey(params, SecureBuffer(sk_raw))
        # Zero the temporary sk_raw since SecureBuffer made a copy
        secure_zero!(sk_raw)
        return (pub, priv)
    finally
        kem_free!(ctx)
    end
end

"""
    encapsulate(pub::MLKEMPublicKey) -> (shared_secret::Vector{UInt8}, encapsulation::Vector{UInt8})

Encapsulate a random shared secret using the public key.
Returns the 32-byte shared secret and the encapsulation (ciphertext) to send to the key holder.

# Example
```julia
shared_secret, encap = encapsulate(pub)
# Send `encap` to the private key holder
```
"""
function encapsulate(pub::MLKEMPublicKey)
    ctx = kem_new(pub.params.alg_name)
    try
        ct, ss = kem_encaps(ctx, pub.data)
        return (ss, ct)
    finally
        kem_free!(ctx)
    end
end

"""
    decapsulate(priv::MLKEMPrivateKey, encapsulation::Vector{UInt8}) -> Vector{UInt8}

Decapsulate a shared secret from the encapsulation using the private key.
Returns the 32-byte shared secret (same as the one returned by `encapsulate`).

# Example
```julia
shared_secret = decapsulate(priv, encap)
```
"""
function decapsulate(priv::MLKEMPrivateKey, encapsulation::Vector{UInt8})
    ctx = kem_new(priv.params.alg_name)
    try
        return kem_decaps(ctx, encapsulation, priv.data.data)
    finally
        kem_free!(ctx)
    end
end
