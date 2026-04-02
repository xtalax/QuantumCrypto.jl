using QuantumCrypto: KEMContext, kem_new, kem_free!, kem_keypair, kem_encaps, kem_decaps,
                     MLKEM512, MLKEM768, MLKEM1024

@testset "liboqs KEM Wrapper" begin
    @testset "kem_new/free for $alg" for alg in [MLKEM512, MLKEM768, MLKEM1024]
        ctx = kem_new(alg)
        @test ctx.ptr != C_NULL
        @test ctx.alg_name == alg
        @test ctx.length_shared_secret == 32
        kem_free!(ctx)
    end

    @testset "known sizes for ML-KEM-512" begin
        ctx = kem_new(MLKEM512)
        @test ctx.length_public_key == 800
        @test ctx.length_secret_key == 1632
        @test ctx.length_ciphertext == 768
        @test ctx.length_shared_secret == 32
        kem_free!(ctx)
    end

    @testset "known sizes for ML-KEM-768" begin
        ctx = kem_new(MLKEM768)
        @test ctx.length_public_key == 1184
        @test ctx.length_secret_key == 2400
        @test ctx.length_ciphertext == 1088
        @test ctx.length_shared_secret == 32
        kem_free!(ctx)
    end

    @testset "known sizes for ML-KEM-1024" begin
        ctx = kem_new(MLKEM1024)
        @test ctx.length_public_key == 1568
        @test ctx.length_secret_key == 3168
        @test ctx.length_ciphertext == 1568
        @test ctx.length_shared_secret == 32
        kem_free!(ctx)
    end

    @testset "invalid algorithm" begin
        @test_throws ErrorException kem_new("NONSENSE-123")
    end

    @testset "round-trip at ccall level" begin
        ctx = kem_new(MLKEM768)
        pk, sk = kem_keypair(ctx)
        ct, ss1 = kem_encaps(ctx, pk)
        ss2 = kem_decaps(ctx, ct, sk)
        @test ss1 == ss2
        @test length(ss1) == 32
        kem_free!(ctx)
    end

    @testset "round-trip for $alg" for alg in [MLKEM512, MLKEM1024]
        ctx = kem_new(alg)
        pk, sk = kem_keypair(ctx)
        ct, ss1 = kem_encaps(ctx, pk)
        ss2 = kem_decaps(ctx, ct, sk)
        @test ss1 == ss2
        kem_free!(ctx)
    end

    @testset "buffer size validation - wrong pk size" begin
        ctx = kem_new(MLKEM768)
        @test_throws ErrorException kem_encaps(ctx, UInt8[1, 2, 3])
        kem_free!(ctx)
    end

    @testset "buffer size validation - wrong ct size" begin
        ctx = kem_new(MLKEM768)
        _, sk = kem_keypair(ctx)
        @test_throws ErrorException kem_decaps(ctx, UInt8[1, 2, 3], sk)
        kem_free!(ctx)
    end

    @testset "buffer size validation - wrong sk size" begin
        ctx = kem_new(MLKEM768)
        pk, _ = kem_keypair(ctx)
        ct, _ = kem_encaps(ctx, pk)
        @test_throws ErrorException kem_decaps(ctx, ct, UInt8[1, 2, 3])
        kem_free!(ctx)
    end

    @testset "keypair outputs correct buffer sizes" begin
        ctx = kem_new(MLKEM768)
        pk, sk = kem_keypair(ctx)
        @test length(pk) == ctx.length_public_key
        @test length(sk) == ctx.length_secret_key
        kem_free!(ctx)
    end

    @testset "encaps outputs correct buffer sizes" begin
        ctx = kem_new(MLKEM768)
        pk, _ = kem_keypair(ctx)
        ct, ss = kem_encaps(ctx, pk)
        @test length(ct) == ctx.length_ciphertext
        @test length(ss) == ctx.length_shared_secret
        kem_free!(ctx)
    end

    @testset "double kem_free! is safe (no double-free)" begin
        ctx = kem_new(MLKEM768)
        kem_free!(ctx)
        @test ctx.ptr == C_NULL
        kem_free!(ctx)  # Must not crash or error
        @test ctx.ptr == C_NULL
    end
end
