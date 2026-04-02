using QuantumCrypto: SIGContext, sig_new, sig_free!, sig_keypair, sig_sign, sig_verify
using QuantumCrypto: MLDSA44, MLDSA65, MLDSA87, SLHDSA_SHA2_128s

@testset "liboqs SIG Wrapper" begin
    @testset "sig_new/free for $alg" for alg in [MLDSA44, MLDSA65, MLDSA87, SLHDSA_SHA2_128s]
        ctx = sig_new(alg)
        @test ctx.ptr != C_NULL
        @test ctx.length_public_key > 0
        @test ctx.length_secret_key > 0
        @test ctx.length_signature > 0
        sig_free!(ctx)
    end

    @testset "double free safety" begin
        ctx = sig_new(MLDSA65)
        sig_free!(ctx)
        sig_free!(ctx)  # Should not crash
        @test ctx.ptr == C_NULL
    end

    @testset "known sizes" begin
        ctx = sig_new(MLDSA65)
        @test ctx.length_public_key == 1952
        @test ctx.length_secret_key == 4032
        @test ctx.length_signature == 3309
        sig_free!(ctx)
    end

    @testset "invalid algorithm" begin
        @test_throws ErrorException sig_new("NONSENSE-SIG-123")
    end

    @testset "round-trip at ccall level for $alg" for alg in [MLDSA44, MLDSA65, MLDSA87]
        ctx = sig_new(alg)
        pk, sk = sig_keypair(ctx)
        msg = Vector{UInt8}("test message for $alg")
        signature = sig_sign(ctx, msg, sk)
        @test length(signature) <= ctx.length_signature
        @test sig_verify(ctx, msg, signature, pk)
        sig_free!(ctx)
    end

    @testset "tampered message fails verification" begin
        ctx = sig_new(MLDSA65)
        pk, sk = sig_keypair(ctx)
        msg = Vector{UInt8}("original message")
        signature = sig_sign(ctx, msg, sk)
        @test !sig_verify(ctx, Vector{UInt8}("tampered message"), signature, pk)
        sig_free!(ctx)
    end

    @testset "wrong key fails verification" begin
        ctx = sig_new(MLDSA65)
        pk1, sk1 = sig_keypair(ctx)
        pk2, sk2 = sig_keypair(ctx)
        msg = Vector{UInt8}("message")
        signature = sig_sign(ctx, msg, sk1)
        @test !sig_verify(ctx, msg, signature, pk2)
        sig_free!(ctx)
    end

    @testset "tampered signature fails" begin
        ctx = sig_new(MLDSA65)
        pk, sk = sig_keypair(ctx)
        msg = Vector{UInt8}("message")
        signature = sig_sign(ctx, msg, sk)
        tampered = copy(signature)
        tampered[1] = tampered[1] ⊻ 0xff
        @test !sig_verify(ctx, msg, tampered, pk)
        sig_free!(ctx)
    end

    @testset "empty message" begin
        ctx = sig_new(MLDSA65)
        pk, sk = sig_keypair(ctx)
        msg = UInt8[]
        signature = sig_sign(ctx, msg, sk)
        @test sig_verify(ctx, msg, signature, pk)
        sig_free!(ctx)
    end

    @testset "buffer size validation" begin
        ctx = sig_new(MLDSA65)
        _, sk = sig_keypair(ctx)
        @test_throws ErrorException sig_sign(ctx, UInt8[1], UInt8[1, 2, 3])  # Wrong sk size
        sig_free!(ctx)
    end

    @testset "SLH-DSA fallback resolution" begin
        # Should work even though liboqs uses SPHINCS+ names internally
        ctx = sig_new(SLHDSA_SHA2_128s)
        @test ctx.ptr != C_NULL
        @test ctx.length_public_key == 32
        @test ctx.length_secret_key == 64
        sig_free!(ctx)
    end
end
