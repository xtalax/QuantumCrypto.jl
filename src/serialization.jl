# PEM serialization for QuantumCrypto key types
#
# Format:
#   -----BEGIN QUANTUMCRYPTO <PUBLIC|PRIVATE> KEY-----
#   Algorithm: <alg_name>
#   <base64-encoded key data, wrapped at 76 chars>
#   -----END QUANTUMCRYPTO <PUBLIC|PRIVATE> KEY-----

using Base64

const PEM_HEADER_PUBLIC  = "-----BEGIN QUANTUMCRYPTO PUBLIC KEY-----"
const PEM_FOOTER_PUBLIC  = "-----END QUANTUMCRYPTO PUBLIC KEY-----"
const PEM_HEADER_PRIVATE = "-----BEGIN QUANTUMCRYPTO PRIVATE KEY-----"
const PEM_FOOTER_PRIVATE = "-----END QUANTUMCRYPTO PRIVATE KEY-----"

# ── Mapping from algorithm name to parameter constants ───────────────────────

const _ALG_TO_KEM_PARAMS = Dict{String,MLKEMParams}(
    "ML-KEM-512"  => ML_KEM_512,
    "ML-KEM-768"  => ML_KEM_768,
    "ML-KEM-1024" => ML_KEM_1024,
)

const _ALG_TO_SIG_PARAMS = Dict{String,SigParams}(
    "ML-DSA-44"          => ML_DSA_44,
    "ML-DSA-65"          => ML_DSA_65,
    "ML-DSA-87"          => ML_DSA_87,
    "SLH-DSA-SHA2-128s"  => SLH_DSA_SHA2_128s,
    "SLH-DSA-SHA2-192s"  => SLH_DSA_SHA2_192s,
    "SLH-DSA-SHA2-256s"  => SLH_DSA_SHA2_256s,
)

# ── Internal formatting ─────────────────────────────────────────────────────

function _format_pem(header::String, footer::String, alg_name::String, data::Vector{UInt8})
    b64 = base64encode(data)
    # Wrap base64 at 76 characters per line (PEM convention)
    wrapped = join([b64[i:min(i + 75, end)] for i in 1:76:length(b64)], "\n")
    return "$header\nAlgorithm: $alg_name\n$wrapped\n$footer\n"
end

# ── to_pem ───────────────────────────────────────────────────────────────────

"""
    to_pem(key) -> String

Serialize a QuantumCrypto key to PEM format.

Supports: `MLKEMPublicKey`, `MLKEMPrivateKey`, `SigPublicKey`, `SigPrivateKey`.
"""
function to_pem(key::MLKEMPublicKey)
    _format_pem(PEM_HEADER_PUBLIC, PEM_FOOTER_PUBLIC, key.params.alg_name, key.data)
end

function to_pem(key::MLKEMPrivateKey)
    _format_pem(PEM_HEADER_PRIVATE, PEM_FOOTER_PRIVATE, key.params.alg_name, key.data.data)
end

function to_pem(key::SigPublicKey)
    _format_pem(PEM_HEADER_PUBLIC, PEM_FOOTER_PUBLIC, key.params.alg_name, key.data)
end

function to_pem(key::SigPrivateKey)
    _format_pem(PEM_HEADER_PRIVATE, PEM_FOOTER_PRIVATE, key.params.alg_name, key.data.data)
end

# ── from_pem ─────────────────────────────────────────────────────────────────

"""
    from_pem(pem::String) -> key

Deserialize a key from PEM format. Returns the appropriate key type based on
the algorithm name and header.

Public keys return `MLKEMPublicKey` or `SigPublicKey`.
Private keys return `MLKEMPrivateKey` or `SigPrivateKey` (with `SecureBuffer`).
"""
function from_pem(pem::String)
    lines = filter(!isempty, strip.(split(strip(pem), '\n')))

    length(lines) >= 4 || throw(ArgumentError("Invalid PEM: too few lines"))

    header = lines[1]
    footer = lines[end]

    # Determine key type
    is_public  = header == PEM_HEADER_PUBLIC  && footer == PEM_FOOTER_PUBLIC
    is_private = header == PEM_HEADER_PRIVATE && footer == PEM_FOOTER_PRIVATE
    (is_public || is_private) || throw(ArgumentError("Invalid PEM: unrecognized header/footer"))

    # Parse algorithm line
    alg_line = lines[2]
    startswith(alg_line, "Algorithm: ") || throw(ArgumentError("Invalid PEM: missing Algorithm line"))
    alg_name = strip(alg_line[length("Algorithm: ")+1:end])

    # Decode base64 data (lines 3 through second-to-last)
    b64_data = join(lines[3:end-1])
    local data::Vector{UInt8}
    try
        data = base64decode(b64_data)
    catch e
        throw(ArgumentError("Invalid PEM: malformed base64 data"))
    end

    # Construct appropriate key type, zeroing raw data for private keys
    try
        if haskey(_ALG_TO_KEM_PARAMS, alg_name)
            params = _ALG_TO_KEM_PARAMS[alg_name]
            return is_public ? MLKEMPublicKey(params, data) : MLKEMPrivateKey(params, SecureBuffer(data))
        elseif haskey(_ALG_TO_SIG_PARAMS, alg_name)
            params = _ALG_TO_SIG_PARAMS[alg_name]
            return is_public ? SigPublicKey(params, data) : SigPrivateKey(params, SecureBuffer(data))
        else
            throw(ArgumentError("Unknown algorithm: $alg_name"))
        end
    finally
        is_private && secure_zero!(data)
    end
end

# ── File I/O convenience ────────────────────────────────────────────────────

"""
    write_pem(path::String, key)

Write a key to a PEM file.
"""
function write_pem(path::String, key)
    open(path, "w") do io
        print(io, to_pem(key))
    end
end

"""
    read_pem(path::String) -> key

Read a key from a PEM file.
"""
function read_pem(path::String)
    from_pem(read(path, String))
end
