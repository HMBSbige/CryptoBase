namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Explicit, Size = 256)]
public ref struct VectorBuffer256
{
	[FieldOffset(0 * 16)] public Vector128<byte> V128_0;
	[FieldOffset(1 * 16)] public Vector128<byte> V128_1;
	[FieldOffset(2 * 16)] public Vector128<byte> V128_2;
	[FieldOffset(3 * 16)] public Vector128<byte> V128_3;
	[FieldOffset(4 * 16)] public Vector128<byte> V128_4;
	[FieldOffset(5 * 16)] public Vector128<byte> V128_5;
	[FieldOffset(6 * 16)] public Vector128<byte> V128_6;
	[FieldOffset(7 * 16)] public Vector128<byte> V128_7;
	[FieldOffset(8 * 16)] public Vector128<byte> V128_8;
	[FieldOffset(9 * 16)] public Vector128<byte> V128_9;
	[FieldOffset(10 * 16)] public Vector128<byte> V128_10;
	[FieldOffset(11 * 16)] public Vector128<byte> V128_11;
	[FieldOffset(12 * 16)] public Vector128<byte> V128_12;
	[FieldOffset(13 * 16)] public Vector128<byte> V128_13;
	[FieldOffset(14 * 16)] public Vector128<byte> V128_14;
	[FieldOffset(15 * 16)] public Vector128<byte> V128_15;

	[FieldOffset(0 * 32)] public Vector256<byte> V256_0;
	[FieldOffset(1 * 32)] public Vector256<byte> V256_1;
	[FieldOffset(2 * 32)] public Vector256<byte> V256_2;
	[FieldOffset(3 * 32)] public Vector256<byte> V256_3;
	[FieldOffset(4 * 32)] public Vector256<byte> V256_4;
	[FieldOffset(5 * 32)] public Vector256<byte> V256_5;
	[FieldOffset(6 * 32)] public Vector256<byte> V256_6;
	[FieldOffset(7 * 32)] public Vector256<byte> V256_7;

	[FieldOffset(0 * 64)] public Vector512<byte> V512_0;
	[FieldOffset(1 * 64)] public Vector512<byte> V512_1;
	[FieldOffset(2 * 64)] public Vector512<byte> V512_2;
	[FieldOffset(3 * 64)] public Vector512<byte> V512_3;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer256 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}
}
