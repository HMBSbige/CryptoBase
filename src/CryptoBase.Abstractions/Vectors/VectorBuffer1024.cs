namespace CryptoBase.Abstractions.Vectors;

/// <summary>Represents a 1,024-byte buffer with overlapping vector and half-buffer views.</summary>
[StructLayout(LayoutKind.Explicit, Size = 1024)]
public struct VectorBuffer1024
{
	/// <summary>The 512-bit vector view of the buffer at byte offset 0.</summary>
	[FieldOffset(0 * 64)] public Vector512<byte> V512_0;
	/// <summary>The 512-bit vector view of the buffer at byte offset 64.</summary>
	[FieldOffset(1 * 64)] public Vector512<byte> V512_1;
	/// <summary>The 512-bit vector view of the buffer at byte offset 128.</summary>
	[FieldOffset(2 * 64)] public Vector512<byte> V512_2;
	/// <summary>The 512-bit vector view of the buffer at byte offset 192.</summary>
	[FieldOffset(3 * 64)] public Vector512<byte> V512_3;
	/// <summary>The 512-bit vector view of the buffer at byte offset 256.</summary>
	[FieldOffset(4 * 64)] public Vector512<byte> V512_4;
	/// <summary>The 512-bit vector view of the buffer at byte offset 320.</summary>
	[FieldOffset(5 * 64)] public Vector512<byte> V512_5;
	/// <summary>The 512-bit vector view of the buffer at byte offset 384.</summary>
	[FieldOffset(6 * 64)] public Vector512<byte> V512_6;
	/// <summary>The 512-bit vector view of the buffer at byte offset 448.</summary>
	[FieldOffset(7 * 64)] public Vector512<byte> V512_7;
	/// <summary>The 512-bit vector view of the buffer at byte offset 512.</summary>
	[FieldOffset(8 * 64)] public Vector512<byte> V512_8;
	/// <summary>The 512-bit vector view of the buffer at byte offset 576.</summary>
	[FieldOffset(9 * 64)] public Vector512<byte> V512_9;
	/// <summary>The 512-bit vector view of the buffer at byte offset 640.</summary>
	[FieldOffset(10 * 64)] public Vector512<byte> V512_10;
	/// <summary>The 512-bit vector view of the buffer at byte offset 704.</summary>
	[FieldOffset(11 * 64)] public Vector512<byte> V512_11;
	/// <summary>The 512-bit vector view of the buffer at byte offset 768.</summary>
	[FieldOffset(12 * 64)] public Vector512<byte> V512_12;
	/// <summary>The 512-bit vector view of the buffer at byte offset 832.</summary>
	[FieldOffset(13 * 64)] public Vector512<byte> V512_13;
	/// <summary>The 512-bit vector view of the buffer at byte offset 896.</summary>
	[FieldOffset(14 * 64)] public Vector512<byte> V512_14;
	/// <summary>The 512-bit vector view of the buffer at byte offset 960.</summary>
	[FieldOffset(15 * 64)] public Vector512<byte> V512_15;

	/// <summary>The lower 512-byte view of the buffer.</summary>
	[FieldOffset(0 * 512)] public VectorBuffer512 Lower;
	/// <summary>The upper 512-byte view of the buffer.</summary>
	[FieldOffset(1 * 512)] public VectorBuffer512 Upper;

	/// <summary>Provides a byte span view of the buffer.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer1024 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}

	/// <summary>Computes the bitwise exclusive OR of two buffers.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer1024 operator ^(in VectorBuffer1024 left, in VectorBuffer1024 right)
	{
		return new VectorBuffer1024
		{
			V512_0 = left.V512_0 ^ right.V512_0,
			V512_1 = left.V512_1 ^ right.V512_1,
			V512_2 = left.V512_2 ^ right.V512_2,
			V512_3 = left.V512_3 ^ right.V512_3,
			V512_4 = left.V512_4 ^ right.V512_4,
			V512_5 = left.V512_5 ^ right.V512_5,
			V512_6 = left.V512_6 ^ right.V512_6,
			V512_7 = left.V512_7 ^ right.V512_7,
			V512_8 = left.V512_8 ^ right.V512_8,
			V512_9 = left.V512_9 ^ right.V512_9,
			V512_10 = left.V512_10 ^ right.V512_10,
			V512_11 = left.V512_11 ^ right.V512_11,
			V512_12 = left.V512_12 ^ right.V512_12,
			V512_13 = left.V512_13 ^ right.V512_13,
			V512_14 = left.V512_14 ^ right.V512_14,
			V512_15 = left.V512_15 ^ right.V512_15
		};
	}
}
