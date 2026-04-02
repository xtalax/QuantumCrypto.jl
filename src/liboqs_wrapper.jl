# liboqs ccall wrapper for ML-KEM (FIPS 203)
#
# Wraps the OQS_KEM API from liboqs via liboqs_jll.
# Uses opaque pointer + offset-based field reads to avoid mirroring the full C struct.

# ── Algorithm name constants ──────────────────────────────────────────────────

const MLKEM512  = "ML-KEM-512"
const MLKEM768  = "ML-KEM-768"
const MLKEM1024 = "ML-KEM-1024"

# ── OQS_STATUS values ────────────────────────────────────────────────────────

const OQS_SUCCESS = Cint(0)
const OQS_ERROR   = Cint(-1)

# ── OQS_KEM struct field offsets (verified against liboqs 0.14 / x86_64) ────
#
# Layout (LP64):
#   0:  const char *method_name
#   8:  const char *alg_version
#  16:  uint8_t claimed_nist_level
#  17:  bool ind_cca
#  18:  (6 bytes padding)
#  24:  size_t length_public_key
#  32:  size_t length_secret_key
#  40:  size_t length_ciphertext
#  48:  size_t length_shared_secret

const _OFFSET_LENGTH_PUBLIC_KEY    = 24
const _OFFSET_LENGTH_SECRET_KEY    = 32
const _OFFSET_LENGTH_CIPHERTEXT    = 40
const _OFFSET_LENGTH_SHARED_SECRET = 48

# ── KEMContext ────────────────────────────────────────────────────────────────

"""
    KEMContext

Opaque handle to a liboqs OQS_KEM instance with cached size parameters.

Fields:
- `ptr`: raw pointer to the C `OQS_KEM` struct (owned by liboqs); nulled after `kem_free!`
- `alg_name`: algorithm identifier string
- `length_public_key`, `length_secret_key`, `length_ciphertext`, `length_shared_secret`: buffer sizes in bytes
"""
mutable struct KEMContext
    ptr::Ptr{Nothing}
    alg_name::String
    length_public_key::Int
    length_secret_key::Int
    length_ciphertext::Int
    length_shared_secret::Int
end

# ── Internal helpers ──────────────────────────────────────────────────────────

"""Read a `Csize_t` field from the OQS_KEM struct at the given byte offset."""
_read_size(ptr::Ptr{Nothing}, offset::Int) = Int(unsafe_load(Ptr{Csize_t}(ptr + offset)))

function _check_status(status::Cint, operation::String)
    if status != OQS_SUCCESS
        error("liboqs $operation failed (OQS_STATUS=$status)")
    end
    nothing
end

# ── Struct offset validation (runs once, lazily) ─────────────────────────────

const _offsets_validated = Ref(false)

function _validate_offsets()
    _offsets_validated[] && return
    ptr = ccall((:OQS_KEM_new, liboqs_jll.liboqs), Ptr{Nothing}, (Cstring,), MLKEM768)
    ptr == C_NULL && error("Cannot validate liboqs struct offsets: ML-KEM-768 not available")
    try
        pk_len = _read_size(ptr, _OFFSET_LENGTH_PUBLIC_KEY)
        sk_len = _read_size(ptr, _OFFSET_LENGTH_SECRET_KEY)
        ct_len = _read_size(ptr, _OFFSET_LENGTH_CIPHERTEXT)
        ss_len = _read_size(ptr, _OFFSET_LENGTH_SHARED_SECRET)
        if pk_len != 1184 || sk_len != 2400 || ct_len != 1088 || ss_len != 32
            error("liboqs OQS_KEM struct layout mismatch: expected ML-KEM-768 sizes " *
                  "(1184, 2400, 1088, 32), got ($pk_len, $sk_len, $ct_len, $ss_len). " *
                  "liboqs_jll version may be incompatible.")
        end
        _offsets_validated[] = true
    finally
        ccall((:OQS_KEM_free, liboqs_jll.liboqs), Cvoid, (Ptr{Nothing},), ptr)
    end
end

# ── Core API ──────────────────────────────────────────────────────────────────

"""
    kem_new(alg_name::String) -> KEMContext

Allocate a new KEM context for the given algorithm (e.g. `MLKEM768`).
Throws on unsupported or disabled algorithm.
"""
function kem_new(alg_name::String)
    _validate_offsets()
    ptr = ccall((:OQS_KEM_new, liboqs_jll.liboqs), Ptr{Nothing}, (Cstring,), alg_name)
    if ptr == C_NULL
        error("OQS_KEM_new failed for \"$alg_name\" — algorithm unsupported or disabled")
    end
    KEMContext(
        ptr,
        alg_name,
        _read_size(ptr, _OFFSET_LENGTH_PUBLIC_KEY),
        _read_size(ptr, _OFFSET_LENGTH_SECRET_KEY),
        _read_size(ptr, _OFFSET_LENGTH_CIPHERTEXT),
        _read_size(ptr, _OFFSET_LENGTH_SHARED_SECRET),
    )
end

"""
    kem_free!(ctx::KEMContext)

Free the underlying liboqs KEM object. Safe to call multiple times — the pointer
is nulled after the first free to prevent double-free.
"""
function kem_free!(ctx::KEMContext)
    if ctx.ptr != C_NULL
        ccall((:OQS_KEM_free, liboqs_jll.liboqs), Cvoid, (Ptr{Nothing},), ctx.ptr)
        ctx.ptr = C_NULL
    end
    nothing
end

"""
    kem_keypair(ctx::KEMContext) -> (public_key::Vector{UInt8}, secret_key::Vector{UInt8})

Generate a fresh KEM keypair.
"""
function kem_keypair(ctx::KEMContext)
    pk = Vector{UInt8}(undef, ctx.length_public_key)
    sk = Vector{UInt8}(undef, ctx.length_secret_key)
    status = ccall(
        (:OQS_KEM_keypair, liboqs_jll.liboqs),
        Cint,
        (Ptr{Nothing}, Ptr{UInt8}, Ptr{UInt8}),
        ctx.ptr, pk, sk,
    )
    _check_status(status, "keypair")
    (pk, sk)
end

"""
    kem_encaps(ctx::KEMContext, public_key::Vector{UInt8}) -> (ciphertext::Vector{UInt8}, shared_secret::Vector{UInt8})

Encapsulate a shared secret using the given public key.
"""
function kem_encaps(ctx::KEMContext, public_key::Vector{UInt8})
    if length(public_key) != ctx.length_public_key
        error("public_key length $(length(public_key)) != expected $(ctx.length_public_key)")
    end
    ct = Vector{UInt8}(undef, ctx.length_ciphertext)
    ss = Vector{UInt8}(undef, ctx.length_shared_secret)
    status = ccall(
        (:OQS_KEM_encaps, liboqs_jll.liboqs),
        Cint,
        (Ptr{Nothing}, Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ctx.ptr, ct, ss, public_key,
    )
    _check_status(status, "encaps")
    (ct, ss)
end

"""
    kem_decaps(ctx::KEMContext, ciphertext::Vector{UInt8}, secret_key::Vector{UInt8}) -> Vector{UInt8}

Decapsulate a shared secret from the ciphertext using the secret key.
"""
function kem_decaps(ctx::KEMContext, ciphertext::Vector{UInt8}, secret_key::Vector{UInt8})
    if length(ciphertext) != ctx.length_ciphertext
        error("ciphertext length $(length(ciphertext)) != expected $(ctx.length_ciphertext)")
    end
    if length(secret_key) != ctx.length_secret_key
        error("secret_key length $(length(secret_key)) != expected $(ctx.length_secret_key)")
    end
    ss = Vector{UInt8}(undef, ctx.length_shared_secret)
    status = ccall(
        (:OQS_KEM_decaps, liboqs_jll.liboqs),
        Cint,
        (Ptr{Nothing}, Ptr{UInt8}, Ptr{UInt8}, Ptr{UInt8}),
        ctx.ptr, ss, ciphertext, secret_key,
    )
    _check_status(status, "decaps")
    ss
end
