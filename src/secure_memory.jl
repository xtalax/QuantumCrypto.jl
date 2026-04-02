# Secure memory management — zeroing buffers for private key material

"""
    secure_zero!(v::Vector{UInt8})

Zero memory using ccall to memset. Unlike `fill!`, this cannot be optimized
away by the compiler because it crosses the FFI boundary.
"""
function secure_zero!(v::Vector{UInt8})
    if !isempty(v)
        ccall(:memset, Ptr{Cvoid}, (Ptr{UInt8}, Cint, Csize_t), v, 0, length(v))
    end
    nothing
end

"""
    SecureBuffer

A buffer that is zeroed when garbage collected. Used for private keys and shared secrets.
The buffer data lives in Julia-managed memory with a finalizer that zeros it.
"""
mutable struct SecureBuffer
    data::Vector{UInt8}

    function SecureBuffer(data::Vector{UInt8})
        buf = new(copy(data))  # Always copy — never alias caller's data
        finalizer(buf) do b
            secure_zero!(b.data)
        end
        buf
    end
end

# Make it indexable and iterable like a Vector{UInt8}
Base.length(b::SecureBuffer) = length(b.data)
Base.getindex(b::SecureBuffer, i...) = getindex(b.data, i...)
Base.pointer(b::SecureBuffer) = pointer(b.data)
Base.sizeof(b::SecureBuffer) = sizeof(b.data)
# Convert to Vector{UInt8} for passing to ccall-based functions
Base.convert(::Type{Vector{UInt8}}, b::SecureBuffer) = b.data

"""
    wipe!(b::SecureBuffer)

Explicitly zero the buffer contents. Call this when you're done with the key
instead of waiting for GC.
"""
function wipe!(b::SecureBuffer)
    secure_zero!(b.data)
    nothing
end
