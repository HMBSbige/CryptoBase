namespace CryptoBase.Abstractions.Vectors;

/// <summary>A 512-byte buffer with overlapping SIMD and half-buffer views.</summary>
[StructLayout(LayoutKind.Explicit, Size = 512)]
public struct VectorBuffer512
{
	/// <summary>The 256-bit byte-vector view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 32)] public Vector256<byte> V256_0;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 32.</summary>
	[FieldOffset(1 * 32)] public Vector256<byte> V256_1;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 64.</summary>
	[FieldOffset(2 * 32)] public Vector256<byte> V256_2;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 96.</summary>
	[FieldOffset(3 * 32)] public Vector256<byte> V256_3;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 128.</summary>
	[FieldOffset(4 * 32)] public Vector256<byte> V256_4;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 160.</summary>
	[FieldOffset(5 * 32)] public Vector256<byte> V256_5;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 192.</summary>
	[FieldOffset(6 * 32)] public Vector256<byte> V256_6;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 224.</summary>
	[FieldOffset(7 * 32)] public Vector256<byte> V256_7;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 256.</summary>
	[FieldOffset(8 * 32)] public Vector256<byte> V256_8;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 288.</summary>
	[FieldOffset(9 * 32)] public Vector256<byte> V256_9;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 320.</summary>
	[FieldOffset(10 * 32)] public Vector256<byte> V256_10;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 352.</summary>
	[FieldOffset(11 * 32)] public Vector256<byte> V256_11;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 384.</summary>
	[FieldOffset(12 * 32)] public Vector256<byte> V256_12;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 416.</summary>
	[FieldOffset(13 * 32)] public Vector256<byte> V256_13;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 448.</summary>
	[FieldOffset(14 * 32)] public Vector256<byte> V256_14;
	/// <summary>The 256-bit byte-vector view beginning at byte offset 480.</summary>
	[FieldOffset(15 * 32)] public Vector256<byte> V256_15;

	/// <summary>The 512-bit byte-vector view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 64)] public Vector512<byte> V512_0;
	/// <summary>The 512-bit byte-vector view beginning at byte offset 64.</summary>
	[FieldOffset(1 * 64)] public Vector512<byte> V512_1;
	/// <summary>The 512-bit byte-vector view beginning at byte offset 128.</summary>
	[FieldOffset(2 * 64)] public Vector512<byte> V512_2;
	/// <summary>The 512-bit byte-vector view beginning at byte offset 192.</summary>
	[FieldOffset(3 * 64)] public Vector512<byte> V512_3;
	/// <summary>The 512-bit byte-vector view beginning at byte offset 256.</summary>
	[FieldOffset(4 * 64)] public Vector512<byte> V512_4;
	/// <summary>The 512-bit byte-vector view beginning at byte offset 320.</summary>
	[FieldOffset(5 * 64)] public Vector512<byte> V512_5;
	/// <summary>The 512-bit byte-vector view beginning at byte offset 384.</summary>
	[FieldOffset(6 * 64)] public Vector512<byte> V512_6;
	/// <summary>The 512-bit byte-vector view beginning at byte offset 448.</summary>
	[FieldOffset(7 * 64)] public Vector512<byte> V512_7;

	/// <summary>The 256-byte buffer view beginning at byte offset 0.</summary>
	[FieldOffset(0 * 256)] public VectorBuffer256 Lower;
	/// <summary>The 256-byte buffer view beginning at byte offset 256.</summary>
	[FieldOffset(1 * 256)] public VectorBuffer256 Upper;

	/// <summary>Converts the buffer to a mutable byte-span view.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer512 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}
}
