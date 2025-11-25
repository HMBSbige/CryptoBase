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
}
