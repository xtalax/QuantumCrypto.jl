# OpenSSL AES-256-GCM AEAD wrapper via ccall into libcrypto

# --- Constants ---

const GCM_IV_LENGTH = 12       # 96-bit IV (NIST recommended for AES-GCM)
const GCM_TAG_LENGTH = 16      # 128-bit authentication tag
const AES256_KEY_LENGTH = 32   # 256-bit key

# EVP control codes for GCM
const EVP_CTRL_GCM_SET_IVLEN = 0x9
const EVP_CTRL_GCM_GET_TAG = 0x10
const EVP_CTRL_GCM_SET_TAG = 0x11

# --- Helpers ---

"""
    random_bytes(n::Int) -> Vector{UInt8}

Generate `n` cryptographically secure random bytes using OpenSSL RAND_bytes.
"""
function random_bytes(n::Int)::Vector{UInt8}
    buf = Vector{UInt8}(undef, n)
    ret = ccall((:RAND_bytes, libcrypto), Cint, (Ptr{UInt8}, Cint), buf, n)
    ret == 1 || error("OpenSSL RAND_bytes failed (returned $ret)")
    return buf
end

# --- Encrypt ---

"""
    aead_encrypt(key::Vector{UInt8}, plaintext::Vector{UInt8}; aad::Vector{UInt8}=UInt8[]) -> Vector{UInt8}

Encrypt `plaintext` with AES-256-GCM. A fresh random 12-byte IV is generated for each call.

Returns a single buffer: `iv (12) || ciphertext || tag (16)`.

`key` must be exactly 32 bytes. Optional `aad` is authenticated but not encrypted.
"""
function aead_encrypt(key::Vector{UInt8}, plaintext::Vector{UInt8}; aad::Vector{UInt8}=UInt8[])
    length(key) == AES256_KEY_LENGTH || throw(ArgumentError("key must be $AES256_KEY_LENGTH bytes, got $(length(key))"))

    iv = random_bytes(GCM_IV_LENGTH)

    ctx = ccall((:EVP_CIPHER_CTX_new, libcrypto), Ptr{Cvoid}, ())
    ctx == C_NULL && error("EVP_CIPHER_CTX_new returned NULL")

    try
        cipher = ccall((:EVP_aes_256_gcm, libcrypto), Ptr{Cvoid}, ())

        # Init cipher context
        ret = ccall((:EVP_EncryptInit_ex, libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}),
                    ctx, cipher, C_NULL, key, iv)
        ret == 1 || error("EVP_EncryptInit_ex failed ($ret)")

        # Process AAD (authenticated associated data) if provided
        if !isempty(aad)
            aad_outl = Ref{Cint}(0)
            ret = ccall((:EVP_EncryptUpdate, libcrypto), Cint,
                        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cint}, Ptr{UInt8}, Cint),
                        ctx, C_NULL, aad_outl, aad, length(aad))
            ret == 1 || error("EVP_EncryptUpdate (AAD) failed ($ret)")
        end

        # Encrypt plaintext
        ciphertext = Vector{UInt8}(undef, length(plaintext))
        outl = Ref{Cint}(0)
        if !isempty(plaintext)
            ret = ccall((:EVP_EncryptUpdate, libcrypto), Cint,
                        (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Cint}, Ptr{UInt8}, Cint),
                        ctx, ciphertext, outl, plaintext, length(plaintext))
            ret == 1 || error("EVP_EncryptUpdate failed ($ret)")
        end
        ct_len = outl[]

        # Finalize (for GCM this produces no additional output, but is required)
        final_outl = Ref{Cint}(0)
        ret = ccall((:EVP_EncryptFinal_ex, libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Cint}),
                    ctx, pointer(ciphertext, ct_len + 1), final_outl)
        ret == 1 || error("EVP_EncryptFinal_ex failed ($ret)")
        ct_len += final_outl[]

        # Extract authentication tag
        tag = Vector{UInt8}(undef, GCM_TAG_LENGTH)
        ret = ccall((:EVP_CIPHER_CTX_ctrl, libcrypto), Cint,
                    (Ptr{Cvoid}, Cint, Cint, Ptr{UInt8}),
                    ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LENGTH, tag)
        ret == 1 || error("EVP_CIPHER_CTX_ctrl (GET_TAG) failed ($ret)")

        # Pack: iv || ciphertext || tag
        return vcat(iv, view(ciphertext, 1:ct_len), tag)
    finally
        ccall((:EVP_CIPHER_CTX_free, libcrypto), Cvoid, (Ptr{Cvoid},), ctx)
    end
end

# --- Decrypt ---

"""
    aead_decrypt(key::Vector{UInt8}, combined::Vector{UInt8}; aad::Vector{UInt8}=UInt8[]) -> Vector{UInt8}

Decrypt an AES-256-GCM message. Input format: `iv (12) || ciphertext || tag (16)`.

Throws an error if authentication fails (tampered or corrupted data).
"""
function aead_decrypt(key::Vector{UInt8}, combined::Vector{UInt8}; aad::Vector{UInt8}=UInt8[])
    length(key) == AES256_KEY_LENGTH || throw(ArgumentError("key must be $AES256_KEY_LENGTH bytes, got $(length(key))"))

    min_len = GCM_IV_LENGTH + GCM_TAG_LENGTH
    length(combined) >= min_len || throw(ArgumentError("combined data too short: need at least $min_len bytes, got $(length(combined))"))

    iv = combined[1:GCM_IV_LENGTH]
    tag = combined[end-GCM_TAG_LENGTH+1:end]
    ciphertext = combined[GCM_IV_LENGTH+1:end-GCM_TAG_LENGTH]

    ctx = ccall((:EVP_CIPHER_CTX_new, libcrypto), Ptr{Cvoid}, ())
    ctx == C_NULL && error("EVP_CIPHER_CTX_new returned NULL")

    try
        cipher = ccall((:EVP_aes_256_gcm, libcrypto), Ptr{Cvoid}, ())

        # Init cipher context
        ret = ccall((:EVP_DecryptInit_ex, libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}),
                    ctx, cipher, C_NULL, key, iv)
        ret == 1 || error("EVP_DecryptInit_ex failed ($ret)")

        # Process AAD if provided
        if !isempty(aad)
            aad_outl = Ref{Cint}(0)
            ret = ccall((:EVP_DecryptUpdate, libcrypto), Cint,
                        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cint}, Ptr{UInt8}, Cint),
                        ctx, C_NULL, aad_outl, aad, length(aad))
            ret == 1 || error("EVP_DecryptUpdate (AAD) failed ($ret)")
        end

        # Decrypt ciphertext
        plaintext = Vector{UInt8}(undef, length(ciphertext))
        outl = Ref{Cint}(0)
        if !isempty(ciphertext)
            ret = ccall((:EVP_DecryptUpdate, libcrypto), Cint,
                        (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Cint}, Ptr{UInt8}, Cint),
                        ctx, plaintext, outl, ciphertext, length(ciphertext))
            ret == 1 || error("EVP_DecryptUpdate failed ($ret)")
        end
        pt_len = outl[]

        # Set expected tag BEFORE finalization (this is where GCM checks authenticity)
        ret = ccall((:EVP_CIPHER_CTX_ctrl, libcrypto), Cint,
                    (Ptr{Cvoid}, Cint, Cint, Ptr{UInt8}),
                    ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LENGTH, tag)
        ret == 1 || error("EVP_CIPHER_CTX_ctrl (SET_TAG) failed ($ret)")

        # Finalize — returns 0 if tag verification fails
        final_outl = Ref{Cint}(0)
        ret = ccall((:EVP_DecryptFinal_ex, libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Cint}),
                    ctx, pointer(plaintext, pt_len + 1), final_outl)
        ret == 1 || error("Authentication failed: ciphertext was tampered with")
        pt_len += final_outl[]

        return plaintext[1:pt_len]
    finally
        ccall((:EVP_CIPHER_CTX_free, libcrypto), Cvoid, (Ptr{Cvoid},), ctx)
    end
end
