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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer64 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}
}
