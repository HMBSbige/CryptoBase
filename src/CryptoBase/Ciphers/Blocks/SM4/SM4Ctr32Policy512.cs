namespace CryptoBase.Ciphers.Blocks.SM4;

internal struct SM4Ctr32Policy512 : ISM4ModePolicy512
{
	private readonly uint _prefix0;
	private readonly uint _prefix1;
	private readonly uint _prefix2;
	private uint _counter;

	internal SM4Ctr32Policy512(Vector128<byte> counter)
	{
		Vector128<uint> value = counter.ReverseEndianness32().AsUInt32();
		_prefix0 = value.GetElement(0);
		_prefix1 = value.GetElement(1);
		_prefix2 = value.GetElement(2);
		_counter = value.GetElement(3);
	}

	internal readonly Vector128<byte> Counter => Vector128.Create(_prefix0, _prefix1, _prefix2, _counter).AsByte().ReverseEndianness32();

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare16(ref byte source, nuint offset, out Vector512<byte> x0, out Vector512<byte> x1, out Vector512<byte> x2, out Vector512<byte> x3)
	{
		x0 = Vector512.Create(_prefix0).AsByte();
		x1 = Vector512.Create(_prefix1).AsByte();
		x2 = Vector512.Create(_prefix2).AsByte();
		x3 = (Vector512.Create(_counter) + SM4Layout.TransposedBlockOffsets16X86).AsByte();
		_counter += 16;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Finish16(ref byte source, ref byte destination, nuint offset, Vector512<byte> x0, Vector512<byte> x1, Vector512<byte> x2, Vector512<byte> x3)
	{
		SM4Layout.XorStore16X86(ref source, ref destination, offset, x0, x1, x2, x3);
	}
}
