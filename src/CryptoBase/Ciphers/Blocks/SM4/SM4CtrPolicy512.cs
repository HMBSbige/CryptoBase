namespace CryptoBase.Ciphers.Blocks.SM4;

internal struct SM4CtrPolicy512 : ISM4ModePolicy512
{
	private ulong _low;
	private ulong _high;

	internal SM4CtrPolicy512(Vector128<byte> counter)
	{
		Vector128<ulong> value = counter.ReverseEndianness128().AsUInt64();
		_low = value.GetElement(0);
		_high = value.GetElement(1);
	}

	internal readonly Vector128<byte> Counter => Vector128.Create(_low, _high).AsByte().ReverseEndianness128();

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare16(ref byte source, nuint offset, out Vector512<byte> x0, out Vector512<byte> x1, out Vector512<byte> x2, out Vector512<byte> x3)
	{
		Vector512<uint> a0 = Vector512.Create((uint)(_high >> 32));
		Vector512<uint> a1 = Vector512.Create((uint)_high);
		Vector512<uint> a2 = Vector512.Create((uint)(_low >> 32));
		Vector512<uint> low = Vector512.Create((uint)_low);
		Vector512<uint> a3 = low + SM4Layout.TransposedBlockOffsets16X86;

		if ((uint)_low > uint.MaxValue - 15)
		{
			Vector512<uint> carry = Vector512.LessThan(a3, low);
			a2 -= carry;
			carry &= Vector512.Equals(a2, Vector512<uint>.Zero);
			a1 -= carry;
			carry &= Vector512.Equals(a1, Vector512<uint>.Zero);
			a0 -= carry;
		}

		_low += 16;
		_high += _low < 16 ? 1UL : 0;
		x0 = a0.AsByte();
		x1 = a1.AsByte();
		x2 = a2.AsByte();
		x3 = a3.AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Finish16(ref byte source, ref byte destination, nuint offset, Vector512<byte> x0, Vector512<byte> x1, Vector512<byte> x2, Vector512<byte> x3)
	{
		SM4Layout.XorStore16X86(ref source, ref destination, offset, x0, x1, x2, x3);
	}
}
