using CryptoBase.Abstractions;

namespace CryptoBase.Macs.GHash;

public sealed class GHashX86 : IMac
{
	public string Name => @"GHash";

	public int Length => 16;

	public const int KeySize = 16;
	public const int BlockSize = 16;

	private readonly Vector128<byte> _key;
	private Vector128<byte> _buffer;

	public GHashX86(scoped ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(key.Length, KeySize, nameof(key));

		ref Vector128<byte> v = ref Unsafe.As<byte, Vector128<byte>>(ref key.GetReference());
		_key = v.ReverseEndianness128();

		Reset();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void GFMul(scoped ReadOnlySpan<byte> x)
	{
		Vector128<ulong> a = _key.AsUInt64();
		Vector128<ulong> b = (Unsafe.As<byte, Vector128<byte>>(ref x.GetReference()).ReverseEndianness128() ^ _buffer).AsUInt64();

		Vector128<uint> tmp3 = Pclmulqdq.CarrylessMultiply(a, b, 0x00).AsUInt32();
		Vector128<uint> tmp4 = Pclmulqdq.CarrylessMultiply(a, b, 0x10).AsUInt32();
		Vector128<uint> tmp5 = Pclmulqdq.CarrylessMultiply(a, b, 0x01).AsUInt32();
		Vector128<uint> tmp6 = Pclmulqdq.CarrylessMultiply(a, b, 0x11).AsUInt32();

		tmp4 ^= tmp5;
		tmp5 = Sse2.ShiftLeftLogical128BitLane(tmp4, 8);
		tmp4 = Sse2.ShiftRightLogical128BitLane(tmp4, 8);
		tmp3 ^= tmp5;
		tmp6 ^= tmp4;

		Vector128<uint> tmp7 = tmp3 >>> 31;
		Vector128<uint> tmp8 = tmp6 >>> 31;
		tmp3 <<= 1;
		tmp6 <<= 1;
		Vector128<uint> tmp9 = Sse2.ShiftRightLogical128BitLane(tmp7, 12);
		tmp8 = Sse2.ShiftLeftLogical128BitLane(tmp8, 4);
		tmp7 = Sse2.ShiftLeftLogical128BitLane(tmp7, 4);
		tmp3 |= tmp7;
		tmp6 |= tmp8;
		tmp6 |= tmp9;
		tmp7 = tmp3 << 31;
		tmp8 = tmp3 << 30;
		tmp9 = tmp3 << 25;
		tmp7 ^= tmp8;
		tmp7 ^= tmp9;
		tmp8 = Sse2.ShiftRightLogical128BitLane(tmp7, 4);
		tmp7 = Sse2.ShiftLeftLogical128BitLane(tmp7, 12);
		tmp3 ^= tmp7;
		Vector128<uint> tmp2 = tmp3 >>> 1;
		tmp4 = Sse2.ShiftRightLogical(tmp3, 2);
		tmp5 = Sse2.ShiftRightLogical(tmp3, 7);
		tmp2 ^= tmp4;
		tmp2 ^= tmp5;
		tmp2 ^= tmp8;
		tmp3 ^= tmp2;
		tmp6 ^= tmp3;

		_buffer = tmp6.AsByte();
	}

	public void Update(scoped ReadOnlySpan<byte> source)
	{
		while (source.Length >= BlockSize)
		{
			GFMul(source);
			source = source[BlockSize..];
		}

		if (source.IsEmpty)
		{
			return;
		}

		Span<byte> block = stackalloc byte[BlockSize];
		source.CopyTo(block);
		GFMul(block);
	}

	public void GetMac(scoped Span<byte> destination)
	{
		_buffer.ReverseEndianness128().CopyTo(destination);
		Reset();
	}

	public void Reset()
	{
		_buffer = default;
	}

	public void Dispose()
	{
	}
}
