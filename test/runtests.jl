using Test
using QuantumCrypto

@testset "QuantumCrypto" begin
    include("test_liboqs_wrapper.jl")
    include("test_aead.jl")
    include("test_secure_memory.jl")
    include("test_kem.jl")
    include("test_kem_dem.jl")
end
