namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Explicit, Size = 64)]
public ref struct VectorBuffer64
{
	[FieldOffset(0 * 16)] public Vector128<byte> V128_0;
	[FieldOffset(1 * 16)] public Vector128<byte> V128_1;
	[FieldOffset(2 * 16)] public Vector128<byte> V128_2;
	[FieldOffset(3 * 16)] public Vector128<byte> V128_3;

	[FieldOffset(0 * 32)] public Vector256<byte> V256_0;
	[FieldOffset(1 * 32)] public Vector256<byte> V256_1;

	[FieldOffset(0 * 64)] public Vector512<byte> V512;

	[FieldOffset(0 * 32)] public VectorBuffer32 Lower;
	[FieldOffset(1 * 32)] public VectorBuffer32 Upper;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer64 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer64 operator ^(scoped in VectorBuffer64 left, scoped in VectorBuffer64 right)
	{
		if (Vector512.IsHardwareAccelerated)
		{
			return new VectorBuffer64 { V512 = left.V512 ^ right.V512 };
		}

		if (Vector256.IsHardwareAccelerated)
		{
			return new VectorBuffer64
			{
				V256_0 = left.V256_0 ^ right.V256_0,
				V256_1 = left.V256_1 ^ right.V256_1
			};
		}

		return new VectorBuffer64
		{
			V128_0 = left.V128_0 ^ right.V128_0,
			V128_1 = left.V128_1 ^ right.V128_1,
			V128_2 = left.V128_2 ^ right.V128_2,
			V128_3 = left.V128_3 ^ right.V128_3
		};
	}
}
