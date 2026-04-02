# High-level digital signature operations wrapping the low-level liboqs SIG API

"""
    keygen(params::SigParams) -> (SigPublicKey, SigPrivateKey)

Generate a fresh signature keypair. The private key is stored in secure memory.

# Example
```julia
pub, priv = keygen(ML_DSA_65)
```
"""
function keygen(params::SigParams)
    ctx = sig_new(params.alg_name)
    try
        pk_raw, sk_raw = sig_keypair(ctx)
        pub = SigPublicKey(params, pk_raw)
        priv = SigPrivateKey(params, SecureBuffer(sk_raw))
        # Zero the temporary sk_raw since SecureBuffer made a copy
        secure_zero!(sk_raw)
        return (pub, priv)
    finally
        sig_free!(ctx)
    end
end

"""
    sign(priv::SigPrivateKey, message::AbstractVector{UInt8}) -> Vector{UInt8}

Sign a message with the private key. Returns the signature bytes.

Extends `Base.sign` — method dispatch on `SigPrivateKey` is disjoint from the
numeric `sign(x::Number)` so there is no ambiguity.

# Example
```julia
signature = sign(priv, Vector{UInt8}("message to sign"))
```
"""
function Base.sign(priv::SigPrivateKey, message::AbstractVector{UInt8})
    ctx = sig_new(priv.params.alg_name)
    try
        return sig_sign(ctx, Vector{UInt8}(message), priv.data.data)
    finally
        sig_free!(ctx)
    end
end

"""
    verify(pub::SigPublicKey, message::AbstractVector{UInt8}, signature::AbstractVector{UInt8}) -> Bool

Verify a signature on a message using the public key.
Returns `true` if valid, `false` if the signature does not verify.

# Example
```julia
is_valid = verify(pub, message, signature)
```
"""
function verify(pub::SigPublicKey, message::AbstractVector{UInt8}, signature::AbstractVector{UInt8})
    ctx = sig_new(pub.params.alg_name)
    try
        return sig_verify(ctx, Vector{UInt8}(message), Vector{UInt8}(signature), pub.data)
    finally
        sig_free!(ctx)
    end
end
