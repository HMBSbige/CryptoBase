using CryptoBase.Ciphers.Blocks.SM4;

namespace CryptoBase.Ciphers.Modes.Ctr;

internal struct SM4CtrPolicy<TIncrementer> : ISM4ModePolicy where TIncrementer : struct, ICtrIncrementer
{
	private uint _w0;
	private uint _w1;
	private uint _w2;
	private uint _w3;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Initialize(Vector128<byte> counter)
	{
		Vector128<uint> value = counter.ReverseEndianness32().AsUInt32();
		_w0 = value.GetElement(0);
		_w1 = value.GetElement(1);
		_w2 = value.GetElement(2);
		_w3 = value.GetElement(3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare8(ref byte source, nuint offset, out Vector256<byte> x0, out Vector256<byte> x1, out Vector256<byte> x2, out Vector256<byte> x3)
	{
		Vector256<uint> a0 = Vector256.Create(_w0);
		Vector256<uint> a1 = Vector256.Create(_w1);
		Vector256<uint> a2 = Vector256.Create(_w2);
		Vector256<uint> low = Vector256.Create(_w3);
		Vector256<uint> a3 = low + SM4Layout.TransposedBlockOffsets8X86;

		if (TIncrementer.CarriesBeyond32 && LanesWrap(8))
		{
			Vector256<uint> carry = Vector256.LessThan(a3, low);
			a2 -= carry;
			carry &= Vector256.Equals(a2, Vector256<uint>.Zero);
			a1 -= carry;
			carry &= Vector256.Equals(a1, Vector256<uint>.Zero);
			a0 -= carry;
		}

		Advance(8);
		x0 = a0.AsByte();
		x1 = a1.AsByte();
		x2 = a2.AsByte();
		x3 = a3.AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Finish8(ref byte source, ref byte destination, nuint offset, Vector256<byte> x0, Vector256<byte> x1, Vector256<byte> x2, Vector256<byte> x3)
	{
		SM4Layout.XorStore8X86(ref source, ref destination, offset, x0, x1, x2, x3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Prepare16(ref byte source, nuint offset, out Vector512<byte> x0, out Vector512<byte> x1, out Vector512<byte> x2, out Vector512<byte> x3)
	{
		Vector512<uint> a0 = Vector512.Create(_w0);
		Vector512<uint> a1 = Vector512.Create(_w1);
		Vector512<uint> a2 = Vector512.Create(_w2);
		Vector512<uint> low = Vector512.Create(_w3);
		Vector512<uint> a3 = low + SM4Layout.TransposedBlockOffsets16X86;

		if (TIncrementer.CarriesBeyond32 && LanesWrap(16))
		{
			Vector512<uint> carry = Vector512.LessThan(a3, low);
			a2 -= carry;
			carry &= Vector512.Equals(a2, Vector512<uint>.Zero);
			a1 -= carry;
			carry &= Vector512.Equals(a1, Vector512<uint>.Zero);
			a0 -= carry;
		}

		Advance(16);
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void SaveState(ref Vector128<byte> counter)
	{
		counter = Vector128.Create(_w0, _w1, _w2, _w3).AsByte().ReverseEndianness32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly bool LanesWrap(int count)
	{
		return _w3 > uint.MaxValue - (uint)(count - 1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Advance(int count)
	{
		uint next = _w3 + (uint)count;
		_w3 = next;

		if (TIncrementer.CarriesBeyond32 && next < (uint)count && ++_w2 is 0 && ++_w1 is 0)
		{
			++_w0;
		}
	}
}
