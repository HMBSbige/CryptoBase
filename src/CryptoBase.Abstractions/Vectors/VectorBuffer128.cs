namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Explicit, Size = 128)]
public ref struct VectorBuffer128
{
	[FieldOffset(0 * 16)] public Vector128<byte> V128_0;
	[FieldOffset(1 * 16)] public Vector128<byte> V128_1;
	[FieldOffset(2 * 16)] public Vector128<byte> V128_2;
	[FieldOffset(3 * 16)] public Vector128<byte> V128_3;
	[FieldOffset(4 * 16)] public Vector128<byte> V128_4;
	[FieldOffset(5 * 16)] public Vector128<byte> V128_5;
	[FieldOffset(6 * 16)] public Vector128<byte> V128_6;
	[FieldOffset(7 * 16)] public Vector128<byte> V128_7;

	[FieldOffset(0 * 32)] public Vector256<byte> V256_0;
	[FieldOffset(1 * 32)] public Vector256<byte> V256_1;
	[FieldOffset(2 * 32)] public Vector256<byte> V256_2;
	[FieldOffset(3 * 32)] public Vector256<byte> V256_3;

	[FieldOffset(0 * 64)] public Vector512<byte> V512_0;
	[FieldOffset(1 * 64)] public Vector512<byte> V512_1;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer128 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}
}
