namespace CryptoBase.Abstractions.Vectors;

/// <summary>A 32-byte buffer with overlapping SIMD and half-buffer views.</summary>
[StructLayout(LayoutKind.Explicit, Size = 32)]
public struct VectorBuffer32
{
	/// <summary>The 128-bit byte-vector view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 16)] public Vector128<byte> V128_0;
	/// <summary>The 128-bit byte-vector view beginning at byte offset 16.</summary>
	[FieldOffset(1 * 16)] public Vector128<byte> V128_1;

	/// <summary>The 256-bit byte-vector view of the entire buffer.</summary>
	[FieldOffset(0 * 32)] public Vector256<byte> V256;

	/// <summary>The 16-byte buffer view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 16)] public VectorBuffer16 Lower;
	/// <summary>The 16-byte buffer view beginning at byte offset 16.</summary>
	[FieldOffset(1 * 16)] public VectorBuffer16 Upper;

	/// <summary>Converts the buffer to a mutable byte-span view.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer32 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}
}
