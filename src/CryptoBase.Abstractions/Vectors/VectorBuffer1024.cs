namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Explicit, Size = 1024)]
public ref struct VectorBuffer1024
{
	[FieldOffset(0 * 64)] public Vector512<byte> V512_0;
	[FieldOffset(1 * 64)] public Vector512<byte> V512_1;
	[FieldOffset(2 * 64)] public Vector512<byte> V512_2;
	[FieldOffset(3 * 64)] public Vector512<byte> V512_3;
	[FieldOffset(4 * 64)] public Vector512<byte> V512_4;
	[FieldOffset(5 * 64)] public Vector512<byte> V512_5;
	[FieldOffset(6 * 64)] public Vector512<byte> V512_6;
	[FieldOffset(7 * 64)] public Vector512<byte> V512_7;
	[FieldOffset(8 * 64)] public Vector512<byte> V512_8;
	[FieldOffset(9 * 64)] public Vector512<byte> V512_9;
	[FieldOffset(10 * 64)] public Vector512<byte> V512_10;
	[FieldOffset(11 * 64)] public Vector512<byte> V512_11;
	[FieldOffset(12 * 64)] public Vector512<byte> V512_12;
	[FieldOffset(13 * 64)] public Vector512<byte> V512_13;
	[FieldOffset(14 * 64)] public Vector512<byte> V512_14;
	[FieldOffset(15 * 64)] public Vector512<byte> V512_15;

	[FieldOffset(0 * 512)] public VectorBuffer512 Lower;
	[FieldOffset(1 * 512)] public VectorBuffer512 Upper;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer1024 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer1024 operator ^(scoped in VectorBuffer1024 left, scoped in VectorBuffer1024 right)
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
