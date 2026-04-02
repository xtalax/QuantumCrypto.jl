using QuantumCrypto: secure_zero!

@testset "Secure Memory" begin
    @testset "secure_zero! zeros a buffer" begin
        v = rand(UInt8, 64)
        @test !all(==(0x00), v)
        secure_zero!(v)
        @test all(==(0x00), v)
    end

    @testset "secure_zero! on empty vector is safe" begin
        v = UInt8[]
        secure_zero!(v)  # Must not error
        @test isempty(v)
    end

    @testset "SecureBuffer basics" begin
        data = rand(UInt8, 32)
        data_copy = copy(data)
        buf = SecureBuffer(data)
        @test length(buf) == 32
        @test buf[1:32] == data_copy
    end

    @testset "SecureBuffer copies input (no aliasing)" begin
        original = rand(UInt8, 32)
        original_copy = copy(original)
        buf = SecureBuffer(original)
        wipe!(buf)
        # Original must be untouched -- SecureBuffer made a copy
        @test original == original_copy
    end

    @testset "wipe! zeros buffer" begin
        data = rand(UInt8, 64)
        buf = SecureBuffer(data)
        @test !all(==(0x00), buf.data)  # Sanity: not already zero
        wipe!(buf)
        @test all(==(0x00), buf.data)
    end

    @testset "wipe! zeros private key material" begin
        _, priv = keygen(ML_KEM_768)
        @test !all(==(0x00), priv.data.data)  # Key should have non-zero content
        wipe!(priv)
        @test all(==(0x00), priv.data.data)
    end

    @testset "SecureBuffer indexing" begin
        data = collect(UInt8, 1:10)
        buf = SecureBuffer(data)
        @test buf[1] == 0x01
        @test buf[10] == 0x0a
        @test buf[3:5] == UInt8[3, 4, 5]
    end

    @testset "SecureBuffer length and sizeof" begin
        buf = SecureBuffer(rand(UInt8, 48))
        @test length(buf) == 48
        @test sizeof(buf) == 48
    end

    @testset "SecureBuffer pointer is valid" begin
        buf = SecureBuffer(rand(UInt8, 16))
        @test pointer(buf) != C_NULL
    end

    @testset "multiple wipe! calls are safe" begin
        buf = SecureBuffer(rand(UInt8, 32))
        wipe!(buf)
        wipe!(buf)  # Should not error
        @test all(==(0x00), buf.data)
    end
end
