using CryptoBase.Abstractions;

namespace CryptoBase.Macs.GHash;

public sealed class GHashX86 : IMac
{
	public string Name => @"GHash";

	public int Length => 16;

	public const int KeySize = 16;
	public const int BlockSize = 16;

	private readonly Vector128<byte> _key1;
	private readonly Vector128<byte> _key2;
	private readonly Vector128<byte> _key3;
	private readonly Vector128<byte> _key4;
	private Vector128<byte> _buffer;

	public GHashX86(scoped ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(key.Length, KeySize, nameof(key));

		ref readonly Vector128<byte> v = ref Unsafe.As<byte, Vector128<byte>>(ref key.GetReference());
		_key1 = v.ReverseEndianness128();
		_key2 = GfMultiply(_key1, _key1);
		_key3 = GfMultiply(_key2, _key1);
		_key4 = GfMultiply(_key3, _key1);

		Reset();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> GfMultiply(Vector128<byte> x, Vector128<byte> y)
	{
		Vector128<ulong> a = x.AsUInt64();
		Vector128<ulong> b = y.AsUInt64();

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
		tmp4 = tmp3 >>> 2;
		tmp5 = tmp3 >>> 7;
		tmp2 ^= tmp4;
		tmp2 ^= tmp5;
		tmp2 ^= tmp8;
		tmp3 ^= tmp2;
		tmp6 ^= tmp3;

		return tmp6.AsByte();
	}

	public void Update(scoped ReadOnlySpan<byte> source)
	{
		int offset = 0;
		int length = source.Length;
		ref byte ptr = ref source.GetReference();

		while (length >= 4 * BlockSize)
		{
			Vector128<byte> x0 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x1 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x2 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 2 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x3 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 3 * BlockSize)).ReverseEndianness128();

			x0 = GfMultiply(_key4, x0 ^ _buffer);
			x1 = GfMultiply(_key3, x1);
			x2 = GfMultiply(_key2, x2);
			x3 = GfMultiply(_key1, x3);
			_buffer = x0 ^ x1 ^ x2 ^ x3;

			offset += 4 * BlockSize;
			length -= 4 * BlockSize;
		}

		if (length >= 2 * BlockSize)
		{
			Vector128<byte> v0 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * BlockSize)).ReverseEndianness128();
			Vector128<byte> v1 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * BlockSize)).ReverseEndianness128();

			v0 = GfMultiply(_key2, v0 ^ _buffer);
			v1 = GfMultiply(_key1, v1);
			_buffer = v0 ^ v1;

			offset += 2 * BlockSize;
			length -= 2 * BlockSize;
		}

		if (length >= BlockSize)
		{
			Vector128<byte> v = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset)).ReverseEndianness128();
			_buffer = GfMultiply(_key1, v ^ _buffer);

			offset += BlockSize;
			length -= BlockSize;
		}

		if (length is not 0)
		{
			Span<byte> block = stackalloc byte[BlockSize];
			source.Slice(offset).CopyTo(block);

			Vector128<byte> v = Unsafe.As<byte, Vector128<byte>>(ref block.GetReference()).ReverseEndianness128();
			_buffer = GfMultiply(_key1, v ^ _buffer);
		}
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
