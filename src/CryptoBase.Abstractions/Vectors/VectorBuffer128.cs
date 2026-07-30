namespace CryptoBase.Abstractions.Vectors;

/// <summary>A 128-byte buffer with overlapping SIMD and half-buffer views.</summary>
[StructLayout(LayoutKind.Explicit, Size = 128)]
public struct VectorBuffer128
{
	/// <summary>The 128-bit byte-vector view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 16)] public Vector128<byte> V128_0;
	/// <summary>The 128-bit byte-vector view beginning at byte offset 16.</summary>
	[FieldOffset(1 * 16)] public Vector128<byte> V128_1;
	/// <summary>The 128-bit byte-vector view beginning at byte offset 32.</summary>
	[FieldOffset(2 * 16)] public Vector128<byte> V128_2;
	/// <summary>The 128-bit byte-vector view beginning at byte offset 48.</summary>
	[FieldOffset(3 * 16)] public Vector128<byte> V128_3;
	/// <summary>The 128-bit byte-vector view beginning at byte offset 64.</summary>
	[FieldOffset(4 * 16)] public Vector128<byte> V128_4;
	/// <summary>The 128-bit byte-vector view beginning at byte offset 80.</summary>
	[FieldOffset(5 * 16)] public Vector128<byte> V128_5;
	/// <summary>The 128-bit byte-vector view beginning at byte offset 96.</summary>
	[FieldOffset(6 * 16)] public Vector128<byte> V128_6;
	/// <summary>The 128-bit byte-vector view beginning at byte offset 112.</summary>
	[FieldOffset(7 * 16)] public Vector128<byte> V128_7;

	/// <summary>The 256-bit byte-vector view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 32)] public Vector256<byte> V256_0;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 32.</summary>
	[FieldOffset(1 * 32)] public Vector256<byte> V256_1;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 64.</summary>
	[FieldOffset(2 * 32)] public Vector256<byte> V256_2;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 96.</summary>
	[FieldOffset(3 * 32)] public Vector256<byte> V256_3;

	/// <summary>The 64-byte buffer view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 64)] public VectorBuffer64 Lower;
	/// <summary>The 64-byte buffer view beginning at byte offset 64.</summary>
	[FieldOffset(1 * 64)] public VectorBuffer64 Upper;

	/// <summary>Converts the buffer to a mutable byte-span view.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer128 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}
}
