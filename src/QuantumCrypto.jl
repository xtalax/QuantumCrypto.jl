module QuantumCrypto

using liboqs_jll
using OpenSSL_jll

include("liboqs_wrapper.jl")
include("openssl_aead.jl")
include("secure_memory.jl")
include("keys.jl")
include("kem.jl")
include("kem_dem.jl")

# Parameter sets
export ML_KEM_512, ML_KEM_768, ML_KEM_1024

# Key types
export MLKEMParams, MLKEMPublicKey, MLKEMPrivateKey

# High-level operations
export keygen, encapsulate, decapsulate, encrypt, decrypt

# Secure memory
export SecureBuffer, wipe!

end # module
