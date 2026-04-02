# X25519 ECDH key agreement via OpenSSL EVP API

const X25519_KEY_LENGTH = 32
const EVP_PKEY_X25519 = 1034

"""
    X25519KeyPair

Ephemeral X25519 key pair. Private key stored in SecureBuffer.
"""
struct X25519KeyPair
    public_key::Vector{UInt8}    # 32 bytes
    private_key::SecureBuffer    # 32 bytes
end

wipe!(kp::X25519KeyPair) = wipe!(kp.private_key)
Base.show(io::IO, ::X25519KeyPair) = print(io, "X25519KeyPair(32 bytes)")

"""
    x25519_keygen() -> X25519KeyPair

Generate a fresh X25519 key pair using OpenSSL `EVP_PKEY_Q_keygen`.
"""
function x25519_keygen()::X25519KeyPair
    pkey = ccall((:EVP_PKEY_Q_keygen, libcrypto), Ptr{Cvoid},
                 (Ptr{Cvoid}, Ptr{Cvoid}, Cstring),
                 C_NULL, C_NULL, "X25519")
    pkey == C_NULL && error("EVP_PKEY_Q_keygen(X25519) returned NULL")

    try
        # Extract raw public key
        pub_len = Ref{Csize_t}(X25519_KEY_LENGTH)
        pub = Vector{UInt8}(undef, X25519_KEY_LENGTH)
        ret = ccall((:EVP_PKEY_get_raw_public_key, libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Csize_t}),
                    pkey, pub, pub_len)
        ret == 1 || error("EVP_PKEY_get_raw_public_key failed ($ret)")

        # Extract raw private key
        priv_len = Ref{Csize_t}(X25519_KEY_LENGTH)
        priv_raw = Vector{UInt8}(undef, X25519_KEY_LENGTH)
        ret = ccall((:EVP_PKEY_get_raw_private_key, libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Csize_t}),
                    pkey, priv_raw, priv_len)
        ret == 1 || error("EVP_PKEY_get_raw_private_key failed ($ret)")

        priv = SecureBuffer(priv_raw)
        secure_zero!(priv_raw)  # Zero the temporary copy
        return X25519KeyPair(pub, priv)
    finally
        ccall((:EVP_PKEY_free, libcrypto), Cvoid, (Ptr{Cvoid},), pkey)
    end
end

"""
    x25519_derive(our_private::SecureBuffer, their_public::Vector{UInt8}) -> Vector{UInt8}

Compute the X25519 shared secret (32 bytes) from our private key and their public key.
"""
function x25519_derive(our_private::SecureBuffer, their_public::Vector{UInt8})::Vector{UInt8}
    length(our_private) == X25519_KEY_LENGTH || throw(ArgumentError("private key must be $X25519_KEY_LENGTH bytes"))
    length(their_public) == X25519_KEY_LENGTH || throw(ArgumentError("public key must be $X25519_KEY_LENGTH bytes"))

    # Reconstruct EVP_PKEY objects from raw bytes
    our_pkey = ccall((:EVP_PKEY_new_raw_private_key, libcrypto), Ptr{Cvoid},
                     (Cint, Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                     EVP_PKEY_X25519, C_NULL, our_private.data, X25519_KEY_LENGTH)
    our_pkey == C_NULL && error("EVP_PKEY_new_raw_private_key failed")

    peer_pkey = C_NULL
    derive_ctx = C_NULL
    try
        peer_pkey = ccall((:EVP_PKEY_new_raw_public_key, libcrypto), Ptr{Cvoid},
                          (Cint, Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                          EVP_PKEY_X25519, C_NULL, their_public, X25519_KEY_LENGTH)
        peer_pkey == C_NULL && error("EVP_PKEY_new_raw_public_key failed")

        # Create derivation context
        derive_ctx = ccall((:EVP_PKEY_CTX_new, libcrypto), Ptr{Cvoid},
                           (Ptr{Cvoid}, Ptr{Cvoid}),
                           our_pkey, C_NULL)
        derive_ctx == C_NULL && error("EVP_PKEY_CTX_new failed")

        ret = ccall((:EVP_PKEY_derive_init, libcrypto), Cint, (Ptr{Cvoid},), derive_ctx)
        ret == 1 || error("EVP_PKEY_derive_init failed ($ret)")

        ret = ccall((:EVP_PKEY_derive_set_peer, libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{Cvoid}),
                    derive_ctx, peer_pkey)
        ret == 1 || error("EVP_PKEY_derive_set_peer failed ($ret)")

        # Derive shared secret
        ss_len = Ref{Csize_t}(0)
        ret = ccall((:EVP_PKEY_derive, libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Csize_t}),
                    derive_ctx, C_NULL, ss_len)
        ret == 1 || error("EVP_PKEY_derive (length query) failed ($ret)")

        shared_secret = Vector{UInt8}(undef, ss_len[])
        ret = ccall((:EVP_PKEY_derive, libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Ptr{Csize_t}),
                    derive_ctx, shared_secret, ss_len)
        ret == 1 || error("EVP_PKEY_derive failed ($ret)")

        return shared_secret
    finally
        derive_ctx != C_NULL && ccall((:EVP_PKEY_CTX_free, libcrypto), Cvoid, (Ptr{Cvoid},), derive_ctx)
        peer_pkey != C_NULL && ccall((:EVP_PKEY_free, libcrypto), Cvoid, (Ptr{Cvoid},), peer_pkey)
        ccall((:EVP_PKEY_free, libcrypto), Cvoid, (Ptr{Cvoid},), our_pkey)
    end
end
