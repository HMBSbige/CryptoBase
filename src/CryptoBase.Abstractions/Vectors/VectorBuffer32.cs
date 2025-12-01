namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Explicit, Size = 32)]
public ref struct VectorBuffer32
{
	[FieldOffset(0 * 16)] public Vector128<byte> V128_0;
	[FieldOffset(1 * 16)] public Vector128<byte> V128_1;

	[FieldOffset(0 * 32)] public Vector256<byte> V256;

	[FieldOffset(0 * 16)] public VectorBuffer16 Lower;
	[FieldOffset(1 * 16)] public VectorBuffer16 Upper;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer32 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer32 operator ^(scoped in VectorBuffer32 left, scoped in VectorBuffer32 right)
	{
		if (Vector256.IsHardwareAccelerated)
		{
			return new VectorBuffer32 { V256 = left.V256 ^ right.V256 };
		}

		return new VectorBuffer32
		{
			V128_0 = left.V128_0 ^ right.V128_0,
			V128_1 = left.V128_1 ^ right.V128_1
		};
	}
}
