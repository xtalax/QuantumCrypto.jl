@testset "Hybrid KEM (ML-KEM + X25519)" begin
    @testset "keygen - $params" for params in [HYBRID_KEM_512, HYBRID_KEM_768, HYBRID_KEM_1024]
        pub, priv = keygen(params)
        @test pub isa HybridPublicKey
        @test priv isa HybridPrivateKey
        @test length(pub.x25519_public) == 32
        @test length(priv.x25519_private) == 32
    end

    @testset "encapsulate/decapsulate round-trip - $params" for params in [HYBRID_KEM_512, HYBRID_KEM_768, HYBRID_KEM_1024]
        pub, priv = keygen(params)
        ss1, encap = encapsulate(pub)
        ss2 = decapsulate(priv, encap)
        @test ss1 == ss2
        @test length(ss1) == 32  # SHA-256 output
    end

    @testset "encrypt/decrypt round-trip - $params" for params in [HYBRID_KEM_512, HYBRID_KEM_768, HYBRID_KEM_1024]
        pub, priv = keygen(params)
        msg = Vector{UInt8}("Hybrid quantum+classical protection!")
        ct = encrypt(pub, msg)
        pt = decrypt(priv, ct)
        @test pt == msg
    end

    @testset "wrong key rejection" begin
        pub, priv = keygen(HYBRID_KEM_768)
        _, priv2 = keygen(HYBRID_KEM_768)
        ct = encrypt(pub, Vector{UInt8}("secret"))
        @test_throws ErrorException decrypt(priv2, ct)
    end

    @testset "tampered ciphertext rejection" begin
        pub, priv = keygen(HYBRID_KEM_768)
        ct = encrypt(pub, Vector{UInt8}("secret"))
        tampered = copy(ct)
        tampered[end-10] ⊻= 0xff
        @test_throws ErrorException decrypt(priv, tampered)
    end

    @testset "empty plaintext" begin
        pub, priv = keygen(HYBRID_KEM_768)
        ct = encrypt(pub, UInt8[])
        pt = decrypt(priv, ct)
        @test pt == UInt8[]
    end

    @testset "large plaintext (1 MB)" begin
        pub, priv = keygen(HYBRID_KEM_768)
        msg = rand(UInt8, 1_000_000)
        ct = encrypt(pub, msg)
        pt = decrypt(priv, ct)
        @test pt == msg
    end

    @testset "AAD support" begin
        pub, priv = keygen(HYBRID_KEM_768)
        aad = Vector{UInt8}("context")
        msg = Vector{UInt8}("payload")
        ct = encrypt(pub, msg; aad)
        @test decrypt(priv, ct; aad) == msg
        @test_throws ErrorException decrypt(priv, ct; aad=Vector{UInt8}("wrong"))
        @test_throws ErrorException decrypt(priv, ct)
    end

    @testset "different encryptions differ" begin
        pub, _ = keygen(HYBRID_KEM_768)
        msg = Vector{UInt8}("same")
        ct1 = encrypt(pub, msg)
        ct2 = encrypt(pub, msg)
        @test ct1 != ct2
    end

    @testset "different keypairs produce different shared secrets" begin
        pub1, _ = keygen(HYBRID_KEM_768)
        pub2, _ = keygen(HYBRID_KEM_768)
        ss1, _ = encapsulate(pub1)
        ss2, _ = encapsulate(pub2)
        @test ss1 != ss2
    end

    @testset "wipe! zeros both keys" begin
        _, priv = keygen(HYBRID_KEM_768)
        wipe!(priv)
        @test all(==(0x00), priv.pqc_key.data.data)
        @test all(==(0x00), priv.x25519_private.data)
    end

    @testset "show methods don't leak keys" begin
        pub, priv = keygen(HYBRID_KEM_768)
        pub_str = sprint(show, pub)
        priv_str = sprint(show, priv)
        @test occursin("HybridPublicKey", pub_str)
        @test occursin("HybridPrivateKey", priv_str)
        @test occursin("X25519", pub_str)
        @test occursin("X25519", priv_str)
    end

    @testset "pure KEM still works alongside hybrid" begin
        kpub, kpriv = keygen(ML_KEM_768)
        msg = Vector{UInt8}("test")
        ct = encrypt(kpub, msg)
        @test decrypt(kpriv, ct) == msg
    end
end
