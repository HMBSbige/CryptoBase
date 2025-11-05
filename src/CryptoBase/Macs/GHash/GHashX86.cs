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
	private readonly Vector128<byte> _key5;
	private readonly Vector128<byte> _key6;
	private readonly Vector128<byte> _key7;
	private readonly Vector128<byte> _key8;

	private Vector128<byte> _buffer;

	public GHashX86(scoped ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(key.Length, KeySize, nameof(key));

		ref readonly Vector128<byte> v = ref Unsafe.As<byte, Vector128<byte>>(ref key.GetReference());
		_key1 = v.ReverseEndianness128();

		_key2 = GHashUtils.GfMultiply(_key1, _key1);
		_key3 = GHashUtils.GfMultiply(_key2, _key1);
		_key4 = GHashUtils.GfMultiply(_key3, _key1);
		_key5 = GHashUtils.GfMultiply(_key4, _key1);
		_key6 = GHashUtils.GfMultiply(_key5, _key1);
		_key7 = GHashUtils.GfMultiply(_key6, _key1);
		_key8 = GHashUtils.GfMultiply(_key7, _key1);

		Reset();
	}

	public void Update(scoped ReadOnlySpan<byte> source)
	{
		int offset = 0;
		int length = source.Length;
		ref byte ptr = ref source.GetReference();

		while (length >= 8 * BlockSize)
		{
			Vector128<byte> x0 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x1 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x2 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 2 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x3 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 3 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x4 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 4 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x5 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 5 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x6 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 6 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x7 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 7 * BlockSize)).ReverseEndianness128();
			x0 ^= _buffer;

			GHashUtils.GfMultiply(_key8, x0, out Vector128<uint> lo0, out Vector128<uint> hi0);
			GHashUtils.GfMultiply(_key7, x1, out Vector128<uint> lo1, out Vector128<uint> hi1);
			GHashUtils.GfMultiply(_key6, x2, out Vector128<uint> lo2, out Vector128<uint> hi2);
			GHashUtils.GfMultiply(_key5, x3, out Vector128<uint> lo3, out Vector128<uint> hi3);
			GHashUtils.GfMultiply(_key4, x4, out Vector128<uint> lo4, out Vector128<uint> hi4);
			GHashUtils.GfMultiply(_key3, x5, out Vector128<uint> lo5, out Vector128<uint> hi5);
			GHashUtils.GfMultiply(_key2, x6, out Vector128<uint> lo6, out Vector128<uint> hi6);
			GHashUtils.GfMultiply(_key1, x7, out Vector128<uint> lo7, out Vector128<uint> hi7);
			Vector128<byte> y0 = GHashUtils.Reduce(lo0, hi0);
			Vector128<byte> y1 = GHashUtils.Reduce(lo1, hi1);
			Vector128<byte> y2 = GHashUtils.Reduce(lo2, hi2);
			Vector128<byte> y3 = GHashUtils.Reduce(lo3, hi3);
			Vector128<byte> y4 = GHashUtils.Reduce(lo4, hi4);
			Vector128<byte> y5 = GHashUtils.Reduce(lo5, hi5);
			Vector128<byte> y6 = GHashUtils.Reduce(lo6, hi6);
			Vector128<byte> y7 = GHashUtils.Reduce(lo7, hi7);

			_buffer = y0 ^ y1 ^ y2 ^ y3 ^ y4 ^ y5 ^ y6 ^ y7;

			offset += 8 * BlockSize;
			length -= 8 * BlockSize;
		}

		while (length >= 4 * BlockSize)
		{
			Vector128<byte> x0 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x1 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x2 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 2 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x3 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 3 * BlockSize)).ReverseEndianness128();
			x0 ^= _buffer;

			GHashUtils.GfMultiply(_key4, x0, out Vector128<uint> lo0, out Vector128<uint> hi0);
			GHashUtils.GfMultiply(_key3, x1, out Vector128<uint> lo1, out Vector128<uint> hi1);
			GHashUtils.GfMultiply(_key2, x2, out Vector128<uint> lo2, out Vector128<uint> hi2);
			GHashUtils.GfMultiply(_key1, x3, out Vector128<uint> lo3, out Vector128<uint> hi3);
			Vector128<byte> y0 = GHashUtils.Reduce(lo0, hi0);
			Vector128<byte> y1 = GHashUtils.Reduce(lo1, hi1);
			Vector128<byte> y2 = GHashUtils.Reduce(lo2, hi2);
			Vector128<byte> y3 = GHashUtils.Reduce(lo3, hi3);

			_buffer = y0 ^ y1 ^ y2 ^ y3;

			offset += 4 * BlockSize;
			length -= 4 * BlockSize;
		}

		if (length >= 2 * BlockSize)
		{
			Vector128<byte> x0 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 0 * BlockSize)).ReverseEndianness128();
			Vector128<byte> x1 = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset + 1 * BlockSize)).ReverseEndianness128();
			x0 ^= _buffer;

			GHashUtils.GfMultiply(_key4, x0, out Vector128<uint> lo0, out Vector128<uint> hi0);
			GHashUtils.GfMultiply(_key3, x1, out Vector128<uint> lo1, out Vector128<uint> hi1);
			Vector128<byte> y0 = GHashUtils.Reduce(lo0, hi0);
			Vector128<byte> y1 = GHashUtils.Reduce(lo1, hi1);

			_buffer = y0 ^ y1;

			offset += 2 * BlockSize;
			length -= 2 * BlockSize;
		}

		if (length >= BlockSize)
		{
			Vector128<byte> v = Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref ptr, offset)).ReverseEndianness128();
			_buffer = GHashUtils.GfMultiply(_key1, v ^ _buffer);

			offset += BlockSize;
			length -= BlockSize;
		}

		if (length is not 0)
		{
			Span<byte> block = stackalloc byte[BlockSize];
			source.Slice(offset).CopyTo(block);

			Vector128<byte> v = Unsafe.As<byte, Vector128<byte>>(ref block.GetReference()).ReverseEndianness128();
			_buffer = GHashUtils.GfMultiply(_key1, v ^ _buffer);
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
