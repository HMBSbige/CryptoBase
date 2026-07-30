namespace CryptoBase.Abstractions.Vectors;

/// <summary>Represents a 256-byte buffer with overlapping vector and half-buffer views.</summary>
[StructLayout(LayoutKind.Explicit, Size = 256)]
public struct VectorBuffer256
{
	/// <summary>The 128-bit vector view of the buffer at byte offset 0.</summary>
	[FieldOffset(0 * 16)] public Vector128<byte> V128_0;
	/// <summary>The 128-bit vector view of the buffer at byte offset 16.</summary>
	[FieldOffset(1 * 16)] public Vector128<byte> V128_1;
	/// <summary>The 128-bit vector view of the buffer at byte offset 32.</summary>
	[FieldOffset(2 * 16)] public Vector128<byte> V128_2;
	/// <summary>The 128-bit vector view of the buffer at byte offset 48.</summary>
	[FieldOffset(3 * 16)] public Vector128<byte> V128_3;
	/// <summary>The 128-bit vector view of the buffer at byte offset 64.</summary>
	[FieldOffset(4 * 16)] public Vector128<byte> V128_4;
	/// <summary>The 128-bit vector view of the buffer at byte offset 80.</summary>
	[FieldOffset(5 * 16)] public Vector128<byte> V128_5;
	/// <summary>The 128-bit vector view of the buffer at byte offset 96.</summary>
	[FieldOffset(6 * 16)] public Vector128<byte> V128_6;
	/// <summary>The 128-bit vector view of the buffer at byte offset 112.</summary>
	[FieldOffset(7 * 16)] public Vector128<byte> V128_7;
	/// <summary>The 128-bit vector view of the buffer at byte offset 128.</summary>
	[FieldOffset(8 * 16)] public Vector128<byte> V128_8;
	/// <summary>The 128-bit vector view of the buffer at byte offset 144.</summary>
	[FieldOffset(9 * 16)] public Vector128<byte> V128_9;
	/// <summary>The 128-bit vector view of the buffer at byte offset 160.</summary>
	[FieldOffset(10 * 16)] public Vector128<byte> V128_10;
	/// <summary>The 128-bit vector view of the buffer at byte offset 176.</summary>
	[FieldOffset(11 * 16)] public Vector128<byte> V128_11;
	/// <summary>The 128-bit vector view of the buffer at byte offset 192.</summary>
	[FieldOffset(12 * 16)] public Vector128<byte> V128_12;
	/// <summary>The 128-bit vector view of the buffer at byte offset 208.</summary>
	[FieldOffset(13 * 16)] public Vector128<byte> V128_13;
	/// <summary>The 128-bit vector view of the buffer at byte offset 224.</summary>
	[FieldOffset(14 * 16)] public Vector128<byte> V128_14;
	/// <summary>The 128-bit vector view of the buffer at byte offset 240.</summary>
	[FieldOffset(15 * 16)] public Vector128<byte> V128_15;

	/// <summary>The 256-bit vector view of the buffer at byte offset 0.</summary>
	[FieldOffset(0 * 32)] public Vector256<byte> V256_0;
	/// <summary>The 256-bit vector view of the buffer at byte offset 32.</summary>
	[FieldOffset(1 * 32)] public Vector256<byte> V256_1;
	/// <summary>The 256-bit vector view of the buffer at byte offset 64.</summary>
	[FieldOffset(2 * 32)] public Vector256<byte> V256_2;
	/// <summary>The 256-bit vector view of the buffer at byte offset 96.</summary>
	[FieldOffset(3 * 32)] public Vector256<byte> V256_3;
	/// <summary>The 256-bit vector view of the buffer at byte offset 128.</summary>
	[FieldOffset(4 * 32)] public Vector256<byte> V256_4;
	/// <summary>The 256-bit vector view of the buffer at byte offset 160.</summary>
	[FieldOffset(5 * 32)] public Vector256<byte> V256_5;
	/// <summary>The 256-bit vector view of the buffer at byte offset 192.</summary>
	[FieldOffset(6 * 32)] public Vector256<byte> V256_6;
	/// <summary>The 256-bit vector view of the buffer at byte offset 224.</summary>
	[FieldOffset(7 * 32)] public Vector256<byte> V256_7;

	/// <summary>The 512-bit vector view of the buffer at byte offset 0.</summary>
	[FieldOffset(0 * 64)] public Vector512<byte> V512_0;
	/// <summary>The 512-bit vector view of the buffer at byte offset 64.</summary>
	[FieldOffset(1 * 64)] public Vector512<byte> V512_1;
	/// <summary>The 512-bit vector view of the buffer at byte offset 128.</summary>
	[FieldOffset(2 * 64)] public Vector512<byte> V512_2;
	/// <summary>The 512-bit vector view of the buffer at byte offset 192.</summary>
	[FieldOffset(3 * 64)] public Vector512<byte> V512_3;

	/// <summary>The lower 128-byte view of the buffer.</summary>
	[FieldOffset(0 * 128)] public VectorBuffer128 Lower;
	/// <summary>The upper 128-byte view of the buffer.</summary>
	[FieldOffset(1 * 128)] public VectorBuffer128 Upper;

	/// <summary>Provides a byte span view of the buffer.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer256 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}
}
