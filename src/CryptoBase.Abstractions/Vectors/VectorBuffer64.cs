namespace CryptoBase.Abstractions.Vectors;

/// <summary>A 64-byte buffer with overlapping SIMD and half-buffer views.</summary>
[StructLayout(LayoutKind.Explicit, Size = 64)]
public struct VectorBuffer64
{
	/// <summary>The 128-bit byte-vector view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 16)] public Vector128<byte> V128_0;
	/// <summary>The 128-bit byte-vector view beginning at byte offset 16.</summary>
	[FieldOffset(1 * 16)] public Vector128<byte> V128_1;
	/// <summary>The 128-bit byte-vector view beginning at byte offset 32.</summary>
	[FieldOffset(2 * 16)] public Vector128<byte> V128_2;
	/// <summary>The 128-bit byte-vector view beginning at byte offset 48.</summary>
	[FieldOffset(3 * 16)] public Vector128<byte> V128_3;

	/// <summary>The 256-bit byte-vector view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 32)] public Vector256<byte> V256_0;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 32.</summary>
	[FieldOffset(1 * 32)] public Vector256<byte> V256_1;

	/// <summary>The 32-byte buffer view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 32)] public VectorBuffer32 Lower;
	/// <summary>The 32-byte buffer view beginning at byte offset 32.</summary>
	[FieldOffset(1 * 32)] public VectorBuffer32 Upper;

	/// <summary>Converts the buffer to a mutable byte-span view.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer64 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}
}
