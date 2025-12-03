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
}
