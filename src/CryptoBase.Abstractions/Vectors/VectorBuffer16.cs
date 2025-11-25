namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Explicit, Size = 16)]
public ref struct VectorBuffer16
{
	[FieldOffset(0 * 16)] public Vector128<byte> V128;

	[FieldOffset(0 * 8)] public ulong Lower;
	[FieldOffset(1 * 8)] public ulong Upper;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer16 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}
}
