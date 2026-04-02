using QuantumCrypto

println("=== Keygen ===")
pub, priv = keygen(ML_KEM_768)
println("Public key: $pub")
println("Private key: $priv")

println("\n=== Raw KEM ===")
ss1, encap = encapsulate(pub)
ss2 = decapsulate(priv, encap)
println("Shared secrets match: $(ss1 == ss2)")
println("Shared secret length: $(length(ss1))")

println("\n=== KEM-DEM Encrypt/Decrypt ===")
message = Vector{UInt8}("Hello, post-quantum world!")
ct = encrypt(pub, message)
println("Plaintext: $(length(message)) bytes")
println("Ciphertext: $(length(ct)) bytes")
pt = decrypt(priv, ct)
println("Decrypted: $(String(copy(pt)))")  # copy() because String() takes ownership of the array
println("Round-trip: $(pt == message)")

println("\n=== Wrong key rejection ===")
pub2, priv2 = keygen(ML_KEM_768)
try
    decrypt(priv2, ct)
    println("ERROR: Should have thrown!")
catch e
    println("Correctly rejected wrong key")
end

println("\n=== Secure memory ===")
_, test_priv = keygen(ML_KEM_512)
wipe!(test_priv)
println("After wipe, key data all zeros: $(all(==(0x00), test_priv.data.data))")

println("\nSUCCESS")
