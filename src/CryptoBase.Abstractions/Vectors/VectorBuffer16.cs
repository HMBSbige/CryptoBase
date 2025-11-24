namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Explicit, Size = 16)]
public ref struct VectorBuffer16
{
	[FieldOffset(0 * 16)] public Vector128<byte> V128;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer16 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}
}
