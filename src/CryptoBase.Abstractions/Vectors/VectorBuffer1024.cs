namespace CryptoBase.Abstractions.Vectors;

[StructLayout(LayoutKind.Explicit, Size = 1024)]
public ref struct VectorBuffer1024
{
	[FieldOffset(0 * 64)] public Vector512<byte> V512_0;
	[FieldOffset(1 * 64)] public Vector512<byte> V512_1;
	[FieldOffset(2 * 64)] public Vector512<byte> V512_2;
	[FieldOffset(3 * 64)] public Vector512<byte> V512_3;
	[FieldOffset(4 * 64)] public Vector512<byte> V512_4;
	[FieldOffset(5 * 64)] public Vector512<byte> V512_5;
	[FieldOffset(6 * 64)] public Vector512<byte> V512_6;
	[FieldOffset(7 * 64)] public Vector512<byte> V512_7;
	[FieldOffset(8 * 64)] public Vector512<byte> V512_8;
	[FieldOffset(9 * 64)] public Vector512<byte> V512_9;
	[FieldOffset(10 * 64)] public Vector512<byte> V512_10;
	[FieldOffset(11 * 64)] public Vector512<byte> V512_11;
	[FieldOffset(12 * 64)] public Vector512<byte> V512_12;
	[FieldOffset(13 * 64)] public Vector512<byte> V512_13;
	[FieldOffset(14 * 64)] public Vector512<byte> V512_14;
	[FieldOffset(15 * 64)] public Vector512<byte> V512_15;

	[FieldOffset(0 * 512)] public VectorBuffer512 Lower;
	[FieldOffset(1 * 512)] public VectorBuffer512 Upper;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static implicit operator Span<byte>(in VectorBuffer1024 value)
	{
		return Unsafe.AsRef(in value).AsSpan();
	}
}
