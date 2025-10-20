namespace CryptoBase.Digests.SM3;

/// <summary>
/// https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
/// </summary>
public sealed class SM3Digest : IHash
{
	private const int BlockSizeOfInt = 16;
	private const int SizeOfInt = sizeof(uint);

	private static readonly uint[] T = new uint[64];

	private static readonly uint[] Init = [0x7380166FU, 0x4914B2B9U, 0x172442D7U, 0xDA8A0600U, 0xA96F30BCU, 0x163138AAU, 0xE38DEE4DU, 0xB0FB0E4EU];

	private ulong _byteCount;
	private int _index;
	private int _bufferIndex;

	private readonly uint[] _v;
	private readonly uint[] _w;
	private readonly byte[] _buffer;

	#region Transformations

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FF0(uint x, uint y, uint z)
	{
		return x ^ y ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FF1(uint x, uint y, uint z)
	{
		return x & y | x & z | y & z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GG0(uint x, uint y, uint z)
	{
		return x ^ y ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GG1(uint x, uint y, uint z)
	{
		return (y ^ z) & x ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint P0(uint x)
	{
		return x ^ x.RotateLeft(9) ^ x.RotateLeft(17);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint P1(uint x)
	{
		return x ^ x.RotateLeft(15) ^ x.RotateLeft(23);
	}

	#endregion

	static SM3Digest()
	{
		for (int i = 0; i < 16; ++i)
		{
			T[i] = 0x79CC4519U.RotateLeft(i);
		}

		for (int i = 16; i < 64; ++i)
		{
			T[i] = 0x7A879D8AU.RotateLeft(i);
		}
	}

	public SM3Digest()
	{
		_w = new uint[68];
		_buffer = new byte[SizeOfInt];
		_v = new uint[8];
		Reset();
	}

	public string Name => @"SM3";

	public int Length => HashConstants.SM3Length;

	public int BlockSize => HashConstants.SM3BlockSize;

	public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		Update(origin);
		GetHash(destination);
	}

	public void Update(ReadOnlySpan<byte> source)
	{
		_byteCount += (uint)source.Length;
		uint[] w = _w;

		if (_bufferIndex != 0)
		{
			int remain = 4 - _bufferIndex;

			if (source.Length < remain)
			{
				source.CopyTo(_buffer.AsSpan(_bufferIndex));
				_bufferIndex += source.Length;
				return;
			}

			source.Slice(0, remain).CopyTo(_buffer.AsSpan(_bufferIndex));
			source = source.Slice(remain);
			w[_index++] = BinaryPrimitives.ReadUInt32BigEndian(_buffer);
			_bufferIndex = 0;
		}

		while (source.Length >= SizeOfInt)
		{
			if (_index is BlockSizeOfInt)
			{
				Process();
				_index = 0;
			}

			w[_index++] = BinaryPrimitives.ReadUInt32BigEndian(source);
			source = source.Slice(SizeOfInt);
		}

		if (_index == BlockSizeOfInt)
		{
			Process();
			_index = 0;
		}

		if (!source.IsEmpty)
		{
			source.CopyTo(_buffer);
			_bufferIndex += source.Length;
		}
	}

	public void GetHash(Span<byte> destination)
	{
		try
		{
			const uint padding = 0b10000000;
			_w[_index++] = _bufferIndex switch
			{
				0 => padding << 24,
				1 => (uint)_buffer[0] << 24 | padding << 16,
				2 => (uint)_buffer[0] << 24 | (uint)_buffer[1] << 16 | padding << 8,
				3 => (uint)_buffer[0] << 24 | (uint)_buffer[1] << 16 | (uint)_buffer[2] << 8 | padding,
				_ => ThrowHelper.ThrowUnreachable<uint>()
			};

			if (_index == 15)
			{
				_w[15] = 0;
			}

			if (_index > 14)// 15 or 16
			{
				Process();
				_index = 0;
			}

			for (int i = _index; i < 14; ++i)
			{
				_w[i] = 0;
			}

			_w[14] = (uint)(_byteCount >> 32 - 3 & 0xFFFFFFFF);
			_w[15] = (uint)(_byteCount << 3 & 0xFFFFFFFF);

			Process();
			BinaryPrimitives.WriteUInt32BigEndian(destination, _v[0]);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), _v[1]);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8), _v[2]);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(12), _v[3]);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(16), _v[4]);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(20), _v[5]);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(24), _v[6]);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(28), _v[7]);
		}
		finally
		{
			Reset();
		}
	}

	public void Reset()
	{
		Init.AsSpan().CopyTo(_v);
		_byteCount = 0;
		_index = 0;
		_bufferIndex = 0;
	}

	private void Process()
	{
		uint[] w = _w;
		uint[] v = _v;

		for (int j = 16; j < 68; ++j)
		{
			w[j] = P1(w[j - 16] ^ w[j - 9] ^ w[j - 3].RotateLeft(15)) ^ w[j - 13].RotateLeft(7) ^ w[j - 6];
		}

		uint a = v[0];
		uint b = v[1];
		uint c = v[2];
		uint d = v[3];
		uint e = v[4];
		uint f = v[5];
		uint g = v[6];
		uint h = v[7];

		for (int j = 0; j < 64; ++j)
		{
			uint a12 = a.RotateLeft(12);
			uint ss1 = (a12 + e + T[j]).RotateLeft(7);
			uint ss2 = ss1 ^ a12;

			uint w1 = w[j] ^ w[j + 4];
			uint tt1, tt2;

			if (j < 16)
			{
				tt1 = FF0(a, b, c) + d + ss2 + w1;
				tt2 = GG0(e, f, g) + h + ss1 + w[j];
			}
			else
			{
				tt1 = FF1(a, b, c) + d + ss2 + w1;
				tt2 = GG1(e, f, g) + h + ss1 + w[j];
			}

			d = c;
			c = b.RotateLeft(9);
			b = a;
			a = tt1;
			h = g;
			g = f.RotateLeft(19);
			f = e;
			e = P0(tt2);
		}

		v[0] ^= a;
		v[1] ^= b;
		v[2] ^= c;
		v[3] ^= d;
		v[4] ^= e;
		v[5] ^= f;
		v[6] ^= g;
		v[7] ^= h;
	}

	public void Dispose()
	{
	}
}
