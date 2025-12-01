namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Explicit, Size = 16)]
public ref struct VectorBuffer16
{
	[FieldOffset(0 * 16)] public Vector128<byte> V128;

	[FieldOffset(0 * 16)] public UInt128 U128;
	[FieldOffset(0 * 16)] public Int128 I128;

	[FieldOffset(0 * 8)] public ulong Lower;
	[FieldOffset(1 * 8)] public ulong Upper;

	[FieldOffset(0 * 4)] public uint U0;
	[FieldOffset(1 * 4)] public uint U1;
	[FieldOffset(2 * 4)] public uint U2;
	[FieldOffset(3 * 4)] public uint U3;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer16 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer16 operator ^(scoped in VectorBuffer16 left, scoped in VectorBuffer16 right)
	{
		if (Vector128.IsHardwareAccelerated)
		{
			return new VectorBuffer16 { V128 = left.V128 ^ right.V128 };
		}

		return new VectorBuffer16 { U128 = left.U128 ^ right.U128 };
	}
}
