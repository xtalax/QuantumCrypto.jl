# KEM-DEM hybrid encryption: ML-KEM key encapsulation + AES-256-GCM symmetric encryption

"""
    encrypt(pub::MLKEMPublicKey, plaintext::AbstractVector{UInt8}; aad::Vector{UInt8}=UInt8[]) -> Vector{UInt8}

Quantum-safe asymmetric encryption using KEM-DEM:
1. ML-KEM encapsulation generates a random shared secret
2. Shared secret used as AES-256-GCM key to encrypt plaintext

Returns a packed buffer:

    [2-byte kem_ct_length (big-endian)] || [kem_ciphertext] || [aead_ciphertext]

The AEAD ciphertext portion is: iv(12) || ciphertext || tag(16).
"""
function encrypt(pub::MLKEMPublicKey, plaintext::AbstractVector{UInt8}; aad::Vector{UInt8}=UInt8[])
    # KEM: generate shared secret
    shared_secret, kem_ct = encapsulate(pub)

    try
        # DEM: encrypt with shared secret as AES-256-GCM key
        aead_ct = aead_encrypt(shared_secret, Vector{UInt8}(plaintext); aad)

        # Pack: [2-byte kem_ct length] || kem_ct || aead_ct
        kem_ct_len = UInt16(length(kem_ct))
        len_bytes = UInt8[UInt8(kem_ct_len >> 8), UInt8(kem_ct_len & 0xFF)]
        return vcat(len_bytes, kem_ct, aead_ct)
    finally
        secure_zero!(shared_secret)  # Zero the ephemeral shared secret
    end
end

"""
    decrypt(priv::MLKEMPrivateKey, ciphertext::AbstractVector{UInt8}; aad::Vector{UInt8}=UInt8[]) -> Vector{UInt8}

Quantum-safe asymmetric decryption (KEM-DEM).
Reverses `encrypt`: decapsulates the shared secret, then decrypts the AEAD portion.

Throws an error if authentication fails (tampered data or wrong key).
"""
function decrypt(priv::MLKEMPrivateKey, ciphertext::AbstractVector{UInt8}; aad::Vector{UInt8}=UInt8[])
    ct = Vector{UInt8}(ciphertext)

    # Unpack: [2-byte kem_ct length] || kem_ct || aead_ct
    length(ct) >= 2 || throw(ArgumentError("ciphertext too short"))
    kem_ct_len = Int(UInt16(ct[1]) << 8 | UInt16(ct[2]))

    length(ct) >= 2 + kem_ct_len || throw(ArgumentError("ciphertext too short for KEM portion"))

    kem_ct = ct[3:2+kem_ct_len]
    aead_ct = ct[3+kem_ct_len:end]

    # KEM: recover shared secret
    shared_secret = decapsulate(priv, kem_ct)

    try
        # DEM: decrypt with shared secret
        return aead_decrypt(shared_secret, aead_ct; aad)
    finally
        secure_zero!(shared_secret)
    end
end
