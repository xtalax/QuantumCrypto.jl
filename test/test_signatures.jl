@testset "Digital Signatures" begin
    @testset "keygen - $params" for params in [ML_DSA_44, ML_DSA_65, ML_DSA_87, SLH_DSA_SHA2_128s]
        pub, priv = keygen(params)
        @test pub isa SigPublicKey
        @test priv isa SigPrivateKey
        @test pub.params.alg_name == params.alg_name
    end

    @testset "sign/verify round-trip - $params" for params in [ML_DSA_44, ML_DSA_65, ML_DSA_87, SLH_DSA_SHA2_128s]
        pub, priv = keygen(params)
        msg = Vector{UInt8}("Hello, quantum signatures!")
        signature = sign(priv, msg)
        @test verify(pub, msg, signature)
    end

    @testset "key sizes - $params" for (params, expected_pk, expected_sk) in [
        (ML_DSA_44, 1312, 2560),
        (ML_DSA_65, 1952, 4032),
        (ML_DSA_87, 2592, 4896),
        (SLH_DSA_SHA2_128s, 32, 64),
    ]
        pub, priv = keygen(params)
        @test length(pub.data) == expected_pk
        @test length(priv.data) == expected_sk
    end

    @testset "tampered message rejection" begin
        pub, priv = keygen(ML_DSA_65)
        msg = Vector{UInt8}("original")
        sig = sign(priv, msg)
        @test !verify(pub, Vector{UInt8}("tampered"), sig)
    end

    @testset "wrong key rejection" begin
        pub1, priv1 = keygen(ML_DSA_65)
        pub2, _ = keygen(ML_DSA_65)
        msg = Vector{UInt8}("message")
        sig = sign(priv1, msg)
        @test !verify(pub2, msg, sig)
    end

    @testset "tampered signature rejection" begin
        pub, priv = keygen(ML_DSA_65)
        msg = Vector{UInt8}("message")
        sig = sign(priv, msg)
        tampered = copy(sig)
        tampered[end] = tampered[end] ⊻ 0xff
        @test !verify(pub, msg, tampered)
    end

    @testset "empty message" begin
        pub, priv = keygen(ML_DSA_65)
        msg = UInt8[]
        sig = sign(priv, msg)
        @test verify(pub, msg, sig)
    end

    @testset "large message (1 MB)" begin
        pub, priv = keygen(ML_DSA_65)
        msg = rand(UInt8, 1_000_000)
        sig = sign(priv, msg)
        @test verify(pub, msg, sig)
    end

    @testset "different messages get different signatures" begin
        pub, priv = keygen(ML_DSA_65)
        sig1 = sign(priv, Vector{UInt8}("message 1"))
        sig2 = sign(priv, Vector{UInt8}("message 2"))
        @test sig1 != sig2
    end

    @testset "same message signed twice — both verify" begin
        pub, priv = keygen(ML_DSA_65)
        msg = Vector{UInt8}("same message")
        sig1 = sign(priv, msg)
        sig2 = sign(priv, msg)
        # ML-DSA uses deterministic signing, so sigs should be equal
        # But both must verify regardless
        @test verify(pub, msg, sig1)
        @test verify(pub, msg, sig2)
    end

    @testset "show methods don't leak key material" begin
        pub, priv = keygen(ML_DSA_65)
        pub_str = sprint(show, pub)
        priv_str = sprint(show, priv)
        @test occursin("SigPublicKey", pub_str)
        @test occursin("SigPrivateKey", priv_str)
        @test occursin("bytes", pub_str)
        @test length(pub_str) < 200
        @test length(priv_str) < 200
    end

    @testset "secure memory wipe" begin
        _, priv = keygen(ML_DSA_65)
        @test !all(==(0x00), priv.data.data)
        wipe!(priv)
        @test all(==(0x00), priv.data.data)
    end

    @testset "KEM and SIG keygen dispatch correctly" begin
        # keygen works for both KEM and SIG params
        kem_pub, kem_priv = keygen(ML_KEM_768)
        sig_pub, sig_priv = keygen(ML_DSA_65)
        @test kem_pub isa MLKEMPublicKey
        @test sig_pub isa SigPublicKey
    end
end
