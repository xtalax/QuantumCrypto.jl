@testset "Key Serialization (PEM)" begin
    @testset "KEM public key round-trip - $params" for params in [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
        pub, _ = keygen(params)
        pem = to_pem(pub)
        pub2 = from_pem(pem)
        @test pub2 isa MLKEMPublicKey
        @test pub2.data == pub.data
        @test pub2.params.alg_name == params.alg_name
    end

    @testset "KEM private key round-trip - $params" for params in [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
        _, priv = keygen(params)
        pem = to_pem(priv)
        priv2 = from_pem(pem)
        @test priv2 isa MLKEMPrivateKey
        @test priv2.data.data == priv.data.data
        @test priv2.params.alg_name == params.alg_name
    end

    @testset "Signature public key round-trip - $params" for params in [ML_DSA_44, ML_DSA_65, ML_DSA_87]
        pub, _ = keygen(params)
        pem = to_pem(pub)
        pub2 = from_pem(pem)
        @test pub2 isa SigPublicKey
        @test pub2.data == pub.data
        @test pub2.params.alg_name == params.alg_name
    end

    @testset "Signature private key round-trip - $params" for params in [ML_DSA_44, ML_DSA_65, ML_DSA_87]
        _, priv = keygen(params)
        pem = to_pem(priv)
        priv2 = from_pem(pem)
        @test priv2 isa SigPrivateKey
        @test priv2.data.data == priv.data.data
        @test priv2.params.alg_name == params.alg_name
    end

    @testset "PEM format correctness" begin
        pub, priv = keygen(ML_KEM_768)
        pub_pem = to_pem(pub)
        priv_pem = to_pem(priv)

        @test startswith(pub_pem, "-----BEGIN QUANTUMCRYPTO PUBLIC KEY-----")
        @test occursin("Algorithm: ML-KEM-768", pub_pem)
        @test endswith(strip(pub_pem), "-----END QUANTUMCRYPTO PUBLIC KEY-----")

        @test startswith(priv_pem, "-----BEGIN QUANTUMCRYPTO PRIVATE KEY-----")
        @test occursin("Algorithm: ML-KEM-768", priv_pem)
        @test endswith(strip(priv_pem), "-----END QUANTUMCRYPTO PRIVATE KEY-----")
    end

    @testset "deserialized KEM key is functional" begin
        pub, priv = keygen(ML_KEM_768)
        pub2 = from_pem(to_pem(pub))
        priv2 = from_pem(to_pem(priv))

        # Encrypt with original, decrypt with deserialized
        ct = encrypt(pub, Vector{UInt8}("test"))
        pt = decrypt(priv2, ct)
        @test pt == Vector{UInt8}("test")

        # Encrypt with deserialized, decrypt with original
        ct2 = encrypt(pub2, Vector{UInt8}("test2"))
        pt2 = decrypt(priv, ct2)
        @test pt2 == Vector{UInt8}("test2")
    end

    @testset "deserialized signature key is functional" begin
        pub, priv = keygen(ML_DSA_65)
        pub2 = from_pem(to_pem(pub))
        priv2 = from_pem(to_pem(priv))

        msg = Vector{UInt8}("sign me")
        sig = sign(priv2, msg)
        @test verify(pub2, msg, sig)

        # Cross: sign with original, verify with deserialized
        sig2 = sign(priv, msg)
        @test verify(pub2, msg, sig2)
    end

    @testset "file I/O" begin
        pub, priv = keygen(ML_KEM_768)
        tmpdir = mktempdir()

        try
            write_pem(joinpath(tmpdir, "pub.pem"), pub)
            write_pem(joinpath(tmpdir, "priv.pem"), priv)

            pub2 = read_pem(joinpath(tmpdir, "pub.pem"))
            priv2 = read_pem(joinpath(tmpdir, "priv.pem"))

            @test pub2.data == pub.data
            @test priv2.data.data == priv.data.data
        finally
            rm(tmpdir; recursive=true)
        end
    end

    @testset "error handling" begin
        @test_throws ArgumentError from_pem("not a pem")
        @test_throws ArgumentError from_pem(
            "-----BEGIN QUANTUMCRYPTO PUBLIC KEY-----\n" *
            "Algorithm: UNKNOWN-ALG\n" *
            "YWJj\n" *
            "-----END QUANTUMCRYPTO PUBLIC KEY-----"
        )
    end

    @testset "private key PEM uses SecureBuffer" begin
        _, priv = keygen(ML_KEM_768)
        pem = to_pem(priv)
        priv2 = from_pem(pem)
        @test priv2.data isa SecureBuffer
    end
end
