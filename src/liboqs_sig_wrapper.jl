# liboqs ccall wrapper for digital signatures (ML-DSA / SLH-DSA)
#
# Wraps the OQS_SIG API from liboqs via liboqs_jll.
# Uses opaque pointer + offset-based field reads to avoid mirroring the full C struct.
# Parallel to liboqs_wrapper.jl which handles KEM operations.

# ── Algorithm name constants ──────────────────────────────────────────────────

# ML-DSA (CRYSTALS-Dilithium) — FIPS 204
const MLDSA44 = "ML-DSA-44"
const MLDSA65 = "ML-DSA-65"
const MLDSA87 = "ML-DSA-87"

# SLH-DSA (SPHINCS+) — FIPS 205
# Note: liboqs_jll may ship these under the legacy "SPHINCS+-*-simple" names
# rather than the NIST "SLH-DSA-*" names. We detect which is available at runtime.
const SLHDSA_SHA2_128s = "SLH-DSA-SHA2-128s"
const SLHDSA_SHA2_192s = "SLH-DSA-SHA2-192s"
const SLHDSA_SHA2_256s = "SLH-DSA-SHA2-256s"

# Legacy SPHINCS+ names (used by older liboqs builds)
const _SPHINCS_SHA2_128s = "SPHINCS+-SHA2-128s-simple"
const _SPHINCS_SHA2_192s = "SPHINCS+-SHA2-192s-simple"
const _SPHINCS_SHA2_256s = "SPHINCS+-SHA2-256s-simple"

# Map SLH-DSA names to SPHINCS+ fallback names
const _SLHDSA_FALLBACK = Dict(
    SLHDSA_SHA2_128s => _SPHINCS_SHA2_128s,
    SLHDSA_SHA2_192s => _SPHINCS_SHA2_192s,
    SLHDSA_SHA2_256s => _SPHINCS_SHA2_256s,
)

"""
    _resolve_sig_alg(name::String) -> String

Resolve a signature algorithm name to the actual string accepted by liboqs.
If the requested name fails (e.g. `SLH-DSA-SHA2-128s`), tries the legacy
`SPHINCS+-*-simple` fallback.
"""
function _resolve_sig_alg(name::String)
    ptr = ccall((:OQS_SIG_new, liboqs_jll.liboqs), Ptr{Nothing}, (Cstring,), name)
    if ptr != C_NULL
        ccall((:OQS_SIG_free, liboqs_jll.liboqs), Cvoid, (Ptr{Nothing},), ptr)
        return name
    end
    fallback = get(_SLHDSA_FALLBACK, name, nothing)
    if fallback !== nothing
        ptr = ccall((:OQS_SIG_new, liboqs_jll.liboqs), Ptr{Nothing}, (Cstring,), fallback)
        if ptr != C_NULL
            ccall((:OQS_SIG_free, liboqs_jll.liboqs), Cvoid, (Ptr{Nothing},), ptr)
            return fallback
        end
    end
    error("Signature algorithm \"$name\" is not available in this liboqs build")
end

# ── OQS_SIG struct field offsets (probed against this build) ─────────────────
#
# Layout (LP64):
#   0:  const char *method_name
#   8:  const char *alg_version
#  16:  uint8_t claimed_nist_level
#  17:  bool euf_cma
#  18:  bool suf_cma  (present in recent liboqs; absent in older versions)
#  19:  (padding / additional bools)
#  20-23: padding
#  24:  size_t length_public_key
#  32:  size_t length_secret_key
#  40:  size_t length_signature

const _SIG_OFFSET_LENGTH_PUBLIC_KEY = 24
const _SIG_OFFSET_LENGTH_SECRET_KEY = 32
const _SIG_OFFSET_LENGTH_SIGNATURE  = 40

# ── SIGContext ───────────────────────────────────────────────────────────────

"""
    SIGContext

Opaque handle to a liboqs OQS_SIG instance with cached size parameters.

Fields:
- `ptr`: raw pointer to the C `OQS_SIG` struct (owned by liboqs); nulled after `sig_free!`
- `alg_name`: algorithm identifier string (the resolved name liboqs actually uses)
- `length_public_key`, `length_secret_key`: buffer sizes in bytes
- `length_signature`: MAXIMUM signature length in bytes (actual may be shorter)
"""
mutable struct SIGContext
    ptr::Ptr{Nothing}
    alg_name::String
    length_public_key::Int
    length_secret_key::Int
    length_signature::Int
end

# ── Struct offset validation (runs once, lazily) ────────────────────────────

const _sig_offsets_validated = Ref(false)

function _validate_sig_offsets()
    _sig_offsets_validated[] && return
    ptr = ccall((:OQS_SIG_new, liboqs_jll.liboqs), Ptr{Nothing}, (Cstring,), MLDSA65)
    ptr == C_NULL && error("Cannot validate liboqs SIG struct offsets: ML-DSA-65 not available")
    try
        pk_len = _read_size(ptr, _SIG_OFFSET_LENGTH_PUBLIC_KEY)
        sk_len = _read_size(ptr, _SIG_OFFSET_LENGTH_SECRET_KEY)
        sig_len = _read_size(ptr, _SIG_OFFSET_LENGTH_SIGNATURE)
        if pk_len != 1952 || sk_len != 4032 || sig_len != 3309
            error("liboqs OQS_SIG struct layout mismatch: expected ML-DSA-65 sizes " *
                  "(1952, 4032, 3309), got ($pk_len, $sk_len, $sig_len). " *
                  "liboqs_jll version may be incompatible.")
        end
        _sig_offsets_validated[] = true
    finally
        ccall((:OQS_SIG_free, liboqs_jll.liboqs), Cvoid, (Ptr{Nothing},), ptr)
    end
end

# ── Core API ─────────────────────────────────────────────────────────────────

"""
    sig_new(alg_name::String) -> SIGContext

Allocate a new signature context for the given algorithm (e.g. `MLDSA65`).
For SLH-DSA names, automatically falls back to SPHINCS+ legacy names if needed.
Throws on unsupported or disabled algorithm.
"""
function sig_new(alg_name::String)
    _validate_sig_offsets()
    resolved = _resolve_sig_alg(alg_name)
    ptr = ccall((:OQS_SIG_new, liboqs_jll.liboqs), Ptr{Nothing}, (Cstring,), resolved)
    if ptr == C_NULL
        error("OQS_SIG_new failed for \"$resolved\" — algorithm unsupported or disabled")
    end
    SIGContext(
        ptr,
        resolved,
        _read_size(ptr, _SIG_OFFSET_LENGTH_PUBLIC_KEY),
        _read_size(ptr, _SIG_OFFSET_LENGTH_SECRET_KEY),
        _read_size(ptr, _SIG_OFFSET_LENGTH_SIGNATURE),
    )
end

"""
    sig_free!(ctx::SIGContext)

Free the underlying liboqs SIG object. Safe to call multiple times — the pointer
is nulled after the first free to prevent double-free.
"""
function sig_free!(ctx::SIGContext)
    if ctx.ptr != C_NULL
        ccall((:OQS_SIG_free, liboqs_jll.liboqs), Cvoid, (Ptr{Nothing},), ctx.ptr)
        ctx.ptr = C_NULL
    end
    nothing
end

"""
    sig_keypair(ctx::SIGContext) -> (public_key::Vector{UInt8}, secret_key::Vector{UInt8})

Generate a fresh signature keypair.
"""
function sig_keypair(ctx::SIGContext)
    pk = Vector{UInt8}(undef, ctx.length_public_key)
    sk = Vector{UInt8}(undef, ctx.length_secret_key)
    status = ccall(
        (:OQS_SIG_keypair, liboqs_jll.liboqs),
        Cint,
        (Ptr{Nothing}, Ptr{UInt8}, Ptr{UInt8}),
        ctx.ptr, pk, sk,
    )
    _check_status(status, "sig_keypair")
    (pk, sk)
end

"""
    sig_sign(ctx::SIGContext, message::Vector{UInt8}, secret_key::Vector{UInt8}) -> Vector{UInt8}

Sign a message using the secret key. Returns the signature (may be shorter than
`ctx.length_signature`, which is the maximum).
"""
function sig_sign(ctx::SIGContext, message::Vector{UInt8}, secret_key::Vector{UInt8})
    if length(secret_key) != ctx.length_secret_key
        error("secret_key length $(length(secret_key)) != expected $(ctx.length_secret_key)")
    end
    sig_buf = Vector{UInt8}(undef, ctx.length_signature)
    sig_len = Ref{Csize_t}(0)
    status = ccall(
        (:OQS_SIG_sign, liboqs_jll.liboqs),
        Cint,
        (Ptr{Nothing}, Ptr{UInt8}, Ref{Csize_t}, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        ctx.ptr, sig_buf, sig_len, message, length(message), secret_key,
    )
    _check_status(status, "sig_sign")
    resize!(sig_buf, sig_len[])
end

"""
    sig_verify(ctx::SIGContext, message::Vector{UInt8}, signature::Vector{UInt8}, public_key::Vector{UInt8}) -> Bool

Verify a signature on a message using the public key.
Returns `true` if valid, `false` if the signature does not verify.
Does NOT throw on verification failure — a false return is the expected API for
"signature invalid".
"""
function sig_verify(ctx::SIGContext, message::Vector{UInt8}, signature::Vector{UInt8}, public_key::Vector{UInt8})
    if length(public_key) != ctx.length_public_key
        error("public_key length $(length(public_key)) != expected $(ctx.length_public_key)")
    end
    status = ccall(
        (:OQS_SIG_verify, liboqs_jll.liboqs),
        Cint,
        (Ptr{Nothing}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}),
        ctx.ptr, message, length(message), signature, length(signature), public_key,
    )
    status == OQS_SUCCESS
end
