@testset "KEM-DEM Encrypt/Decrypt" begin
    @testset "round-trip - $params" for params in [ML_KEM_512, ML_KEM_768, ML_KEM_1024]
        pub, priv = keygen(params)
        plaintext = Vector{UInt8}("Hello, post-quantum world!")
        ct = encrypt(pub, plaintext)
        pt = decrypt(priv, ct)
        @test pt == plaintext
    end

    @testset "empty plaintext" begin
        pub, priv = keygen(ML_KEM_768)
        ct = encrypt(pub, UInt8[])
        pt = decrypt(priv, ct)
        @test pt == UInt8[]
    end

    @testset "large plaintext (1 MB)" begin
        pub, priv = keygen(ML_KEM_768)
        plaintext = rand(UInt8, 1_000_000)
        ct = encrypt(pub, plaintext)
        pt = decrypt(priv, ct)
        @test pt == plaintext
    end

    @testset "ciphertext overhead - $label" for (label, params, kem_ct_size) in [
        ("ML-KEM-512",  ML_KEM_512,  768),
        ("ML-KEM-768",  ML_KEM_768,  1088),
        ("ML-KEM-1024", ML_KEM_1024, 1568),
    ]
        pub, _ = keygen(params)
        plaintext = Vector{UInt8}("test")
        ct = encrypt(pub, plaintext)
        # Overhead = 2 (length prefix) + kem_ct_size + 12 (IV) + 16 (tag)
        expected_overhead = 2 + kem_ct_size + 12 + 16
        @test length(ct) == length(plaintext) + expected_overhead
    end

    @testset "wrong key rejection" begin
        pub, _ = keygen(ML_KEM_768)
        _, priv_wrong = keygen(ML_KEM_768)
        ct = encrypt(pub, Vector{UInt8}("secret"))
        # ML-KEM implicit rejection gives wrong shared secret -> AES-GCM auth fails
        @test_throws ErrorException decrypt(priv_wrong, ct)
    end

    @testset "tampered AEAD portion rejection" begin
        pub, priv = keygen(ML_KEM_768)
        ct = encrypt(pub, Vector{UInt8}("secret"))
        tampered = copy(ct)
        # Flip a byte in the AEAD portion (after 2-byte header + KEM ciphertext)
        tampered[end-20] = xor(tampered[end-20], 0xff)
        @test_throws ErrorException decrypt(priv, tampered)
    end

    @testset "tampered KEM ciphertext rejection" begin
        pub, priv = keygen(ML_KEM_768)
        ct = encrypt(pub, Vector{UInt8}("secret"))
        tampered = copy(ct)
        # Flip a byte in the KEM portion (after 2-byte header)
        tampered[10] = xor(tampered[10], 0xff)
        @test_throws ErrorException decrypt(priv, tampered)
    end

    @testset "truncated ciphertext - too short for header" begin
        _, priv = keygen(ML_KEM_768)
        @test_throws ArgumentError decrypt(priv, UInt8[0x01])
    end

    @testset "truncated ciphertext - too short for KEM CT" begin
        _, priv = keygen(ML_KEM_768)
        # Header says 1088 bytes of KEM CT but we only provide 8 bytes total
        @test_throws ArgumentError decrypt(priv, UInt8[0x04, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    end

    @testset "AAD (additional authenticated data)" begin
        pub, priv = keygen(ML_KEM_768)
        aad = Vector{UInt8}("context-binding-data")
        plaintext = Vector{UInt8}("secret payload")
        ct = encrypt(pub, plaintext; aad)

        # Correct AAD -> decrypts fine
        pt = decrypt(priv, ct; aad)
        @test pt == plaintext

        # Wrong AAD -> auth failure
        @test_throws ErrorException decrypt(priv, ct; aad=Vector{UInt8}("wrong-context"))

        # Missing AAD -> auth failure
        @test_throws ErrorException decrypt(priv, ct)
    end

    @testset "different encryptions of same plaintext differ" begin
        pub, _ = keygen(ML_KEM_768)
        pt = Vector{UInt8}("same message")
        ct1 = encrypt(pub, pt)
        ct2 = encrypt(pub, pt)
        @test ct1 != ct2  # Different KEM coins + different AES-GCM IVs
    end

    @testset "wire format structure" begin
        pub, priv = keygen(ML_KEM_768)
        ct = encrypt(pub, Vector{UInt8}("hello"))

        # First 2 bytes are big-endian KEM CT length
        kem_ct_len = Int(UInt16(ct[1]) << 8 | UInt16(ct[2]))
        @test kem_ct_len == 1088  # ML-KEM-768 CT size

        # Total = 2 + kem_ct_len + GCM_IV(12) + plaintext(5) + GCM_TAG(16)
        @test length(ct) == 2 + 1088 + 12 + 5 + 16
    end

    @testset "binary data round-trip (all byte values)" begin
        pub, priv = keygen(ML_KEM_768)
        # Every possible byte value
        plaintext = collect(UInt8, 0x00:0xff)
        ct = encrypt(pub, plaintext)
        pt = decrypt(priv, ct)
        @test pt == plaintext
    end
end
