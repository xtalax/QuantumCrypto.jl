module QuantumCrypto

using liboqs_jll
using OpenSSL_jll

include("liboqs_wrapper.jl")
include("liboqs_sig_wrapper.jl")
include("openssl_aead.jl")
include("secure_memory.jl")
include("keys.jl")
include("kem.jl")
include("kem_dem.jl")
include("sig_keys.jl")
include("signatures.jl")

# KEM parameter sets
export ML_KEM_512, ML_KEM_768, ML_KEM_1024

# KEM key types
export MLKEMParams, MLKEMPublicKey, MLKEMPrivateKey

# KEM operations
export keygen, encapsulate, decapsulate, encrypt, decrypt

# Signature parameter sets
export ML_DSA_44, ML_DSA_65, ML_DSA_87
export SLH_DSA_SHA2_128s, SLH_DSA_SHA2_192s, SLH_DSA_SHA2_256s

# Signature key types
export SigParams, SigPublicKey, SigPrivateKey

# Signature operations (sign extends Base.sign — no export needed)
export verify

# Secure memory
export SecureBuffer, wipe!

end # module
