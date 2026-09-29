namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly struct SM4DirectPolicy512 : ISM4ModePolicy512
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare16(ref byte source, nuint offset, out Vector512<byte> x0, out Vector512<byte> x1, out Vector512<byte> x2, out Vector512<byte> x3)
	{
		SM4Layout.Load16X86(16, ref source, offset, out x0, out x1, out x2, out x3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Finish16(ref byte source, ref byte destination, nuint offset, Vector512<byte> x0, Vector512<byte> x1, Vector512<byte> x2, Vector512<byte> x3)
	{
		SM4Layout.Store16X86(16, ref destination, offset, x0, x1, x2, x3);
	}
}
