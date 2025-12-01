namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Explicit, Size = 512)]
public ref struct VectorBuffer512
{
	[FieldOffset(0 * 32)] public Vector256<byte> V256_0;
	[FieldOffset(1 * 32)] public Vector256<byte> V256_1;
	[FieldOffset(2 * 32)] public Vector256<byte> V256_2;
	[FieldOffset(3 * 32)] public Vector256<byte> V256_3;
	[FieldOffset(4 * 32)] public Vector256<byte> V256_4;
	[FieldOffset(5 * 32)] public Vector256<byte> V256_5;
	[FieldOffset(6 * 32)] public Vector256<byte> V256_6;
	[FieldOffset(7 * 32)] public Vector256<byte> V256_7;
	[FieldOffset(8 * 32)] public Vector256<byte> V256_8;
	[FieldOffset(9 * 32)] public Vector256<byte> V256_9;
	[FieldOffset(10 * 32)] public Vector256<byte> V256_10;
	[FieldOffset(11 * 32)] public Vector256<byte> V256_11;
	[FieldOffset(12 * 32)] public Vector256<byte> V256_12;
	[FieldOffset(13 * 32)] public Vector256<byte> V256_13;
	[FieldOffset(14 * 32)] public Vector256<byte> V256_14;
	[FieldOffset(15 * 32)] public Vector256<byte> V256_15;

	[FieldOffset(0 * 64)] public Vector512<byte> V512_0;
	[FieldOffset(1 * 64)] public Vector512<byte> V512_1;
	[FieldOffset(2 * 64)] public Vector512<byte> V512_2;
	[FieldOffset(3 * 64)] public Vector512<byte> V512_3;
	[FieldOffset(4 * 64)] public Vector512<byte> V512_4;
	[FieldOffset(5 * 64)] public Vector512<byte> V512_5;
	[FieldOffset(6 * 64)] public Vector512<byte> V512_6;
	[FieldOffset(7 * 64)] public Vector512<byte> V512_7;

	[FieldOffset(0 * 256)] public VectorBuffer256 Lower;
	[FieldOffset(1 * 256)] public VectorBuffer256 Upper;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer512 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer512 operator ^(scoped in VectorBuffer512 left, scoped in VectorBuffer512 right)
	{
		if (Vector512.IsHardwareAccelerated)
		{
			return new VectorBuffer512
			{
				V512_0 = left.V512_0 ^ right.V512_0,
				V512_1 = left.V512_1 ^ right.V512_1,
				V512_2 = left.V512_2 ^ right.V512_2,
				V512_3 = left.V512_3 ^ right.V512_3,
				V512_4 = left.V512_4 ^ right.V512_4,
				V512_5 = left.V512_5 ^ right.V512_5,
				V512_6 = left.V512_6 ^ right.V512_6,
				V512_7 = left.V512_7 ^ right.V512_7
			};
		}

		return new VectorBuffer512
		{
			V256_0 = left.V256_0 ^ right.V256_0,
			V256_1 = left.V256_1 ^ right.V256_1,
			V256_2 = left.V256_2 ^ right.V256_2,
			V256_3 = left.V256_3 ^ right.V256_3,
			V256_4 = left.V256_4 ^ right.V256_4,
			V256_5 = left.V256_5 ^ right.V256_5,
			V256_6 = left.V256_6 ^ right.V256_6,
			V256_7 = left.V256_7 ^ right.V256_7,
			V256_8 = left.V256_8 ^ right.V256_8,
			V256_9 = left.V256_9 ^ right.V256_9,
			V256_10 = left.V256_10 ^ right.V256_10,
			V256_11 = left.V256_11 ^ right.V256_11,
			V256_12 = left.V256_12 ^ right.V256_12,
			V256_13 = left.V256_13 ^ right.V256_13,
			V256_14 = left.V256_14 ^ right.V256_14,
			V256_15 = left.V256_15 ^ right.V256_15
		};
	}
}
