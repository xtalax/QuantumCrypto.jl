# Hybrid KEM: ML-KEM (post-quantum) + X25519 (classical) key encapsulation
#
# Both KEMs run independently. Shared secrets are combined via SHA-256(pqc_ss || x25519_ss).
# An attacker must break BOTH to recover the combined shared secret.

# --- SHA-256 via OpenSSL ---

"""
    sha256(data::Vector{UInt8}) -> Vector{UInt8}

Compute SHA-256 hash of `data`. Returns 32-byte digest.
"""
function sha256(data::Vector{UInt8})::Vector{UInt8}
    out = Vector{UInt8}(undef, 32)
    ret = ccall((:SHA256, libcrypto), Ptr{UInt8},
                (Ptr{UInt8}, Csize_t, Ptr{UInt8}),
                data, length(data), out)
    ret == C_NULL && error("SHA256 returned NULL")
    return out
end

# --- Hybrid parameter types ---

"""
    HybridParams

Hybrid parameter set combining an ML-KEM variant with X25519.
Use the constants `HYBRID_KEM_512`, `HYBRID_KEM_768`, `HYBRID_KEM_1024`.
"""
struct HybridParams
    pqc_params::MLKEMParams
end

const HYBRID_KEM_512  = HybridParams(ML_KEM_512)
const HYBRID_KEM_768  = HybridParams(ML_KEM_768)
const HYBRID_KEM_1024 = HybridParams(ML_KEM_1024)

"""
    HybridPublicKey

Hybrid public key: ML-KEM public key + X25519 public key (32 bytes).
"""
struct HybridPublicKey
    pqc_key::MLKEMPublicKey
    x25519_public::Vector{UInt8}
end

"""
    HybridPrivateKey

Hybrid private key: ML-KEM private key + X25519 private key (SecureBuffer).
"""
struct HybridPrivateKey
    pqc_key::MLKEMPrivateKey
    x25519_private::SecureBuffer
end

wipe!(k::HybridPrivateKey) = (wipe!(k.pqc_key); wipe!(k.x25519_private))

Base.show(io::IO, k::HybridPublicKey) = print(io, "HybridPublicKey($(k.pqc_key.params.alg_name) + X25519)")
Base.show(io::IO, k::HybridPrivateKey) = print(io, "HybridPrivateKey($(k.pqc_key.params.alg_name) + X25519)")

# --- Hybrid KEM operations ---

"""
    keygen(params::HybridParams) -> (HybridPublicKey, HybridPrivateKey)

Generate a hybrid key pair (ML-KEM + X25519).
"""
function keygen(params::HybridParams)
    pqc_pub, pqc_priv = keygen(params.pqc_params)
    x25519 = x25519_keygen()
    pub = HybridPublicKey(pqc_pub, x25519.public_key)
    priv = HybridPrivateKey(pqc_priv, x25519.private_key)
    return (pub, priv)
end

"""
    encapsulate(pub::HybridPublicKey) -> (shared_secret::Vector{UInt8}, encapsulation::Vector{UInt8})

Hybrid encapsulation: ML-KEM encapsulate + ephemeral X25519 ECDH.
Shared secrets are combined via SHA-256(pqc_ss || x25519_ss).

Encapsulation format: `[pqc_ciphertext] || [ephemeral_x25519_public (32 bytes)]`
"""
function encapsulate(pub::HybridPublicKey)
    # 1. ML-KEM encapsulate
    pqc_ss, pqc_ct = encapsulate(pub.pqc_key)

    # 2. X25519 ephemeral ECDH
    ephemeral = x25519_keygen()
    x25519_ss = x25519_derive(ephemeral.private_key, pub.x25519_public)

    try
        # 3. Combine: SHA-256(pqc_ss || x25519_ss)
        combined_ss = sha256(vcat(pqc_ss, x25519_ss))

        # 4. Pack: pqc_ciphertext || ephemeral_x25519_public
        encap = vcat(pqc_ct, ephemeral.public_key)

        return (combined_ss, encap)
    finally
        secure_zero!(pqc_ss)
        secure_zero!(x25519_ss)
        wipe!(ephemeral.private_key)
    end
end

"""
    decapsulate(priv::HybridPrivateKey, encapsulation::Vector{UInt8}) -> Vector{UInt8}

Hybrid decapsulation: split encapsulation, ML-KEM decapsulate + X25519 derive.
Returns SHA-256(pqc_ss || x25519_ss).
"""
function decapsulate(priv::HybridPrivateKey, encapsulation::Vector{UInt8})
    # Determine PQC ciphertext length from the algorithm parameters
    ctx = kem_new(priv.pqc_key.params.alg_name)
    pqc_ct_len = ctx.length_ciphertext
    kem_free!(ctx)

    expected_len = pqc_ct_len + X25519_KEY_LENGTH
    length(encapsulation) == expected_len ||
        throw(ArgumentError("encapsulation length $(length(encapsulation)) != expected $expected_len"))

    pqc_ct = encapsulation[1:pqc_ct_len]
    peer_x25519_pub = encapsulation[pqc_ct_len+1:end]

    # 1. ML-KEM decapsulate
    pqc_ss = decapsulate(priv.pqc_key, pqc_ct)

    # 2. X25519 derive
    x25519_ss = x25519_derive(priv.x25519_private, peer_x25519_pub)

    try
        # 3. Combine: SHA-256(pqc_ss || x25519_ss)
        return sha256(vcat(pqc_ss, x25519_ss))
    finally
        secure_zero!(pqc_ss)
        secure_zero!(x25519_ss)
    end
end

# --- Hybrid encrypt/decrypt (KEM-DEM) ---

"""
    encrypt(pub::HybridPublicKey, plaintext::AbstractVector{UInt8}; aad::Vector{UInt8}=UInt8[]) -> Vector{UInt8}

Hybrid quantum-safe encryption: hybrid KEM + AES-256-GCM.

Returns: `[2-byte hybrid_ct_length (big-endian)] || [hybrid_ciphertext] || [aead_ciphertext]`
"""
function encrypt(pub::HybridPublicKey, plaintext::AbstractVector{UInt8}; aad::Vector{UInt8}=UInt8[])
    shared_secret, hybrid_ct = encapsulate(pub)
    try
        aead_ct = aead_encrypt(shared_secret, Vector{UInt8}(plaintext); aad)
        ct_len = UInt16(length(hybrid_ct))
        len_bytes = UInt8[UInt8(ct_len >> 8), UInt8(ct_len & 0xFF)]
        return vcat(len_bytes, hybrid_ct, aead_ct)
    finally
        secure_zero!(shared_secret)
    end
end

"""
    decrypt(priv::HybridPrivateKey, ciphertext::AbstractVector{UInt8}; aad::Vector{UInt8}=UInt8[]) -> Vector{UInt8}

Hybrid quantum-safe decryption. Reverses `encrypt`.
Throws on authentication failure (tampered data or wrong key).
"""
function decrypt(priv::HybridPrivateKey, ciphertext::AbstractVector{UInt8}; aad::Vector{UInt8}=UInt8[])
    ct = Vector{UInt8}(ciphertext)
    length(ct) >= 2 || throw(ArgumentError("ciphertext too short"))

    hybrid_ct_len = Int(UInt16(ct[1]) << 8 | UInt16(ct[2]))
    length(ct) >= 2 + hybrid_ct_len || throw(ArgumentError("ciphertext too short for hybrid portion"))

    hybrid_ct = ct[3:2+hybrid_ct_len]
    aead_ct = ct[3+hybrid_ct_len:end]

    shared_secret = decapsulate(priv, hybrid_ct)
    try
        return aead_decrypt(shared_secret, aead_ct; aad)
    finally
        secure_zero!(shared_secret)
    end
end
