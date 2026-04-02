using QuantumCrypto: aead_encrypt, aead_decrypt, random_bytes,
                     AES256_KEY_LENGTH, GCM_IV_LENGTH, GCM_TAG_LENGTH

@testset "AES-256-GCM AEAD" begin
    @testset "round-trip" begin
        key = random_bytes(AES256_KEY_LENGTH)
        pt = Vector{UInt8}("test plaintext")
        ct = aead_encrypt(key, pt)
        result = aead_decrypt(key, ct)
        @test result == pt
    end

    @testset "output format: iv || ciphertext || tag" begin
        key = random_bytes(AES256_KEY_LENGTH)
        pt = Vector{UInt8}("hello")
        ct = aead_encrypt(key, pt)
        @test length(ct) == GCM_IV_LENGTH + length(pt) + GCM_TAG_LENGTH
    end

    @testset "wrong key rejection" begin
        key1 = random_bytes(AES256_KEY_LENGTH)
        key2 = random_bytes(AES256_KEY_LENGTH)
        ct = aead_encrypt(key1, Vector{UInt8}("secret"))
        @test_throws ErrorException aead_decrypt(key2, ct)
    end

    @testset "tampered ciphertext data rejection" begin
        key = random_bytes(AES256_KEY_LENGTH)
        ct = aead_encrypt(key, Vector{UInt8}("secret"))
        tampered = copy(ct)
        tampered[GCM_IV_LENGTH + 1] = xor(tampered[GCM_IV_LENGTH + 1], 0xff)
        @test_throws ErrorException aead_decrypt(key, tampered)
    end

    @testset "tampered IV rejection" begin
        key = random_bytes(AES256_KEY_LENGTH)
        ct = aead_encrypt(key, Vector{UInt8}("secret"))
        tampered = copy(ct)
        tampered[1] = xor(tampered[1], 0xff)
        @test_throws ErrorException aead_decrypt(key, tampered)
    end

    @testset "tampered tag rejection" begin
        key = random_bytes(AES256_KEY_LENGTH)
        ct = aead_encrypt(key, Vector{UInt8}("secret"))
        tampered = copy(ct)
        tampered[end] = xor(tampered[end], 0xff)
        @test_throws ErrorException aead_decrypt(key, tampered)
    end

    @testset "empty plaintext" begin
        key = random_bytes(AES256_KEY_LENGTH)
        ct = aead_encrypt(key, UInt8[])
        pt = aead_decrypt(key, ct)
        @test pt == UInt8[]
        @test length(ct) == GCM_IV_LENGTH + GCM_TAG_LENGTH
    end

    @testset "bad key length - encrypt" begin
        @test_throws ArgumentError aead_encrypt(rand(UInt8, 16), UInt8[1])
        @test_throws ArgumentError aead_encrypt(rand(UInt8, 0), UInt8[1])
        @test_throws ArgumentError aead_encrypt(rand(UInt8, 64), UInt8[1])
    end

    @testset "bad key length - decrypt" begin
        @test_throws ArgumentError aead_decrypt(rand(UInt8, 16), rand(UInt8, 30))
        @test_throws ArgumentError aead_decrypt(rand(UInt8, 0), rand(UInt8, 30))
    end

    @testset "combined data too short for decrypt" begin
        key = random_bytes(AES256_KEY_LENGTH)
        # Minimum is GCM_IV_LENGTH + GCM_TAG_LENGTH = 28 bytes
        @test_throws ArgumentError aead_decrypt(key, rand(UInt8, 10))
        @test_throws ArgumentError aead_decrypt(key, UInt8[])
    end

    @testset "random_bytes produces different output" begin
        a = random_bytes(32)
        b = random_bytes(32)
        @test a != b
        @test length(a) == 32
    end

    @testset "random IVs make each encryption unique" begin
        key = random_bytes(AES256_KEY_LENGTH)
        pt = Vector{UInt8}("same")
        ct1 = aead_encrypt(key, pt)
        ct2 = aead_encrypt(key, pt)
        @test ct1 != ct2
        # But both decrypt correctly
        @test aead_decrypt(key, ct1) == pt
        @test aead_decrypt(key, ct2) == pt
    end

    @testset "AAD round-trip" begin
        key = random_bytes(AES256_KEY_LENGTH)
        pt = Vector{UInt8}("payload")
        aad = Vector{UInt8}("context")
        ct = aead_encrypt(key, pt; aad)
        result = aead_decrypt(key, ct; aad)
        @test result == pt
    end

    @testset "wrong AAD rejected" begin
        key = random_bytes(AES256_KEY_LENGTH)
        pt = Vector{UInt8}("payload")
        aad = Vector{UInt8}("context")
        ct = aead_encrypt(key, pt; aad)
        @test_throws ErrorException aead_decrypt(key, ct; aad=Vector{UInt8}("wrong"))
    end

    @testset "missing AAD rejected when AAD was used" begin
        key = random_bytes(AES256_KEY_LENGTH)
        pt = Vector{UInt8}("payload")
        aad = Vector{UInt8}("context")
        ct = aead_encrypt(key, pt; aad)
        @test_throws ErrorException aead_decrypt(key, ct)
    end

    @testset "large plaintext (64 KB)" begin
        key = random_bytes(AES256_KEY_LENGTH)
        pt = rand(UInt8, 65536)
        ct = aead_encrypt(key, pt)
        result = aead_decrypt(key, ct)
        @test result == pt
    end
end
