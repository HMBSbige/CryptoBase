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

	[FieldOffset(0 * 64)] public VectorBuffer64 Lower;
	[FieldOffset(1 * 64)] public VectorBuffer64 Upper;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer128 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer128 operator ^(scoped in VectorBuffer128 left, scoped in VectorBuffer128 right)
	{
		if (Vector256.IsHardwareAccelerated)
		{
			return new VectorBuffer128
			{
				V256_0 = left.V256_0 ^ right.V256_0,
				V256_1 = left.V256_1 ^ right.V256_1,
				V256_2 = left.V256_2 ^ right.V256_2,
				V256_3 = left.V256_3 ^ right.V256_3
			};
		}

		return new VectorBuffer128
		{
			V128_0 = left.V128_0 ^ right.V128_0,
			V128_1 = left.V128_1 ^ right.V128_1,
			V128_2 = left.V128_2 ^ right.V128_2,
			V128_3 = left.V128_3 ^ right.V128_3,
			V128_4 = left.V128_4 ^ right.V128_4,
			V128_5 = left.V128_5 ^ right.V128_5,
			V128_6 = left.V128_6 ^ right.V128_6,
			V128_7 = left.V128_7 ^ right.V128_7
		};
	}
}
