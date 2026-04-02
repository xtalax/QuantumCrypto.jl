@testset "ML-KEM Key Encapsulation" begin
    @testset "keygen produces valid types - $params" for params in [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
        pub, priv = keygen(params)
        @test pub isa MLKEMPublicKey
        @test priv isa MLKEMPrivateKey
        @test pub.params.alg_name == params.alg_name
        @test priv.params.alg_name == params.alg_name
    end

    @testset "key sizes - $label" for (label, params, expected_pk, expected_sk, expected_ct) in [
        ("ML-KEM-512",  ML_KEM_512,  800,  1632, 768),
        ("ML-KEM-768",  ML_KEM_768,  1184, 2400, 1088),
        ("ML-KEM-1024", ML_KEM_1024, 1568, 3168, 1568),
    ]
        pub, priv = keygen(params)
        @test length(pub.data) == expected_pk
        @test length(priv.data) == expected_sk

        _, encap = encapsulate(pub)
        @test length(encap) == expected_ct
    end

    @testset "encapsulate/decapsulate round-trip - $params" for params in [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
        pub, priv = keygen(params)
        ss1, encap = encapsulate(pub)
        ss2 = decapsulate(priv, encap)
        @test ss1 == ss2
        @test length(ss1) == 32  # Shared secret is always 32 bytes
    end

    @testset "different keypairs produce different shared secrets" begin
        pub1, _ = keygen(ML_KEM_768)
        pub2, _ = keygen(ML_KEM_768)
        ss1, _ = encapsulate(pub1)
        ss2, _ = encapsulate(pub2)
        @test ss1 != ss2
    end

    @testset "wrong private key produces different shared secret (implicit rejection)" begin
        pub, priv = keygen(ML_KEM_768)
        _, priv_wrong = keygen(ML_KEM_768)
        ss_orig, encap = encapsulate(pub)
        ss_wrong = decapsulate(priv_wrong, encap)
        @test ss_orig != ss_wrong
    end

    @testset "multiple encapsulations produce different results" begin
        pub, _ = keygen(ML_KEM_768)
        ss1, ct1 = encapsulate(pub)
        ss2, ct2 = encapsulate(pub)
        @test ss1 != ss2
        @test ct1 != ct2
    end

    @testset "show methods don't leak key material" begin
        pub, priv = keygen(ML_KEM_768)
        pub_str = sprint(show, pub)
        priv_str = sprint(show, priv)
        @test occursin("MLKEMPublicKey", pub_str)
        @test occursin("MLKEMPrivateKey", priv_str)
        @test occursin("bytes", pub_str)
        @test occursin("bytes", priv_str)
        # Ensure no raw hex dump -- output should be short summary
        @test length(pub_str) < 200
        @test length(priv_str) < 200
    end

    @testset "show includes algorithm name" begin
        pub, priv = keygen(ML_KEM_512)
        @test occursin("ML-KEM-512", sprint(show, pub))
        @test occursin("ML-KEM-512", sprint(show, priv))
    end

    @testset "keygen zeroes temporary sk buffer" begin
        # This is a behavioral test: keygen should call fill!(sk_raw, 0x00)
        # We can't directly observe this, but we verify the private key itself is valid
        pub, priv = keygen(ML_KEM_768)
        ss1, encap = encapsulate(pub)
        ss2 = decapsulate(priv, encap)
        @test ss1 == ss2  # Key must still work despite sk_raw being wiped
    end
end
