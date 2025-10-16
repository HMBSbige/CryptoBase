using CryptoBase.Abstractions;
using System.Security.Cryptography;

namespace CryptoBase.Macs.GHash;

public sealed class GHashSF : IMac
{
	public string Name => @"GHash";

	public int Length => 16;

	public const int KeySize = 16;
	public const int BlockSize = 16;

	private static readonly ulong[] Last4 = [0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0];

	private readonly ulong[] _hh;
	private readonly ulong[] _hl;
	private readonly byte[] _buffer;

	private readonly ulong Initvh;
	private readonly ulong Initvl;

	public GHashSF(scoped ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(key.Length, KeySize, nameof(key));

		Initvh = BinaryPrimitives.ReadUInt64BigEndian(key);
		Initvl = BinaryPrimitives.ReadUInt64BigEndian(key[8..]);

		_hl = ArrayPool<ulong>.Shared.Rent(BlockSize);
		_hh = ArrayPool<ulong>.Shared.Rent(BlockSize);
		_buffer = ArrayPool<byte>.Shared.Rent(BlockSize);

		Reset();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void GFMul(scoped ReadOnlySpan<byte> x)
	{
		for (int i = 0; i < BlockSize; ++i)
		{
			_buffer[i] ^= x[i];
		}

		byte lo = (byte)(_buffer[15] & 0xF);
		ulong zh = _hh[lo];
		ulong zl = _hl[lo];

		for (int i = 0; i < BlockSize; ++i)
		{
			lo = (byte)(_buffer[16 - 1 - i] & 0xf);
			byte hi = (byte)(_buffer[16 - 1 - i] >> 4 & 0xf);

			byte rem;

			if (i != 0)
			{
				rem = (byte)(zl & 0xf);
				zl = zh << 60 | zl >> 4;
				zh >>= 4;
				zh ^= Last4[rem] << 48;
				zh ^= _hh[lo];
				zl ^= _hl[lo];
			}

			rem = (byte)(zl & 0xf);
			zl = zh << 60 | zl >> 4;
			zh >>= 4;

			zh ^= Last4[rem] << 48;
			zh ^= _hh[hi];
			zl ^= _hl[hi];
		}

		BinaryPrimitives.WriteUInt64BigEndian(_buffer, zh);
		BinaryPrimitives.WriteUInt64BigEndian(_buffer.AsSpan(8), zl);
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
		_buffer.AsSpan(0, Length).CopyTo(destination);

		Reset();
	}

	public void Reset()
	{
		CryptographicOperations.ZeroMemory(_buffer.AsSpan(0, BlockSize));

		ulong vh = Initvh;
		ulong vl = Initvl;

		_hl[8] = vl;
		_hh[8] = vh;

		uint i = 4u;

		while (i > 0)
		{
			ulong t = (vl & 1) * 0xe1000000;
			vl = vh << 63 | vl >> 1;
			vh = vh >> 1 ^ t << 32;

			_hl[i] = vl;
			_hh[i] = vh;

			i >>= 1;
		}

		i = 2u;

		while (i <= 8)
		{
			vh = _hh[i];
			vl = _hl[i];

			for (uint j = 1u; j < i; ++j)
			{
				_hh[i + j] = vh ^ _hh[j];
				_hl[i + j] = vl ^ _hl[j];
			}

			i <<= 1;
		}
	}

	public void Dispose()
	{
		ArrayPool<ulong>.Shared.Return(_hl);
		ArrayPool<ulong>.Shared.Return(_hh);
		ArrayPool<byte>.Shared.Return(_buffer);
	}
}
