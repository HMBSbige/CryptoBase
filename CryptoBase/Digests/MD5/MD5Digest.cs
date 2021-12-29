using CryptoBase.Abstractions.Digests;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace CryptoBase.Digests.MD5;

/// <summary>
/// https://tools.ietf.org/html/rfc1321
/// </summary>
public class MD5Digest : IHash
{
	protected const int BlockSizeOfInt = 16;
	protected const int SizeOfInt = sizeof(uint);

	protected uint A, B, C, D;
	private ulong _byteCount;
	private int _index;
	private int _bufferIndex;

	protected readonly uint[] X;
	private readonly byte[] _buffer;

	#region S

	private const int S11 = 7;
	private const int S12 = 12;
	private const int S13 = 17;
	private const int S14 = 22;
	private const int S21 = 5;
	private const int S22 = 9;
	private const int S23 = 14;
	private const int S24 = 20;
	private const int S31 = 4;
	private const int S32 = 11;
	private const int S33 = 16;
	private const int S34 = 23;
	private const int S41 = 6;
	private const int S42 = 10;
	private const int S43 = 15;
	private const int S44 = 21;

	#endregion

	#region Basic

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint F(uint x, uint y, uint z)
	{
		return (y ^ z) & x ^ z;
		//return (x & y) | IntrinsicsUtils.AndNot(x, z);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint G(uint x, uint y, uint z)
	{
		return (x ^ y) & z ^ y;
		//return (z & x) | IntrinsicsUtils.AndNot(z, y);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint H(uint x, uint y, uint z)
	{
		return x ^ y ^ z;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint I(uint x, uint y, uint z)
	{
		return y ^ (x | ~z);
	}

	#endregion

	#region Transformations

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FF(uint a, uint b, uint c, uint d, uint mj, int s, uint ti)
	{
		a += F(b, c, d) + mj + ti;
		return a.RotateLeft(s) + b;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GG(uint a, uint b, uint c, uint d, uint mj, int s, uint ti)
	{
		a += G(b, c, d) + mj + ti;
		return a.RotateLeft(s) + b;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint HH(uint a, uint b, uint c, uint d, uint mj, int s, uint ti)
	{
		a += H(b, c, d) + mj + ti;
		return a.RotateLeft(s) + b;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint II(uint a, uint b, uint c, uint d, uint mj, int s, uint ti)
	{
		a += I(b, c, d) + mj + ti;
		return a.RotateLeft(s) + b;
	}

	#endregion

	public MD5Digest()
	{
		X = new uint[BlockSizeOfInt];
		_buffer = new byte[SizeOfInt];
		Reset();
	}

	public string Name => @"MD5";

	public int Length => HashConstants.Md5Length;

	public int BlockSize => HashConstants.Md5BlockSize;

	public virtual void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		Update(origin);
		GetHash(destination);
	}

	public virtual void Update(ReadOnlySpan<byte> source)
	{
		_byteCount += (uint)source.Length;

		if (_bufferIndex != 0)
		{
			var remain = 4 - _bufferIndex;
			if (source.Length < remain)
			{
				source.CopyTo(_buffer.AsSpan(_bufferIndex));
				_bufferIndex += source.Length;
				return;
			}

			source[..remain].CopyTo(_buffer.AsSpan(_bufferIndex));
			source = source[remain..];
			X[_index++] = BinaryPrimitives.ReadUInt32LittleEndian(_buffer);
			_bufferIndex = 0;
		}

		while (source.Length >= SizeOfInt)
		{
			if (_index == BlockSizeOfInt)
			{
				Process();
				_index = 0;
			}

			X[_index++] = BinaryPrimitives.ReadUInt32LittleEndian(source);
			source = source[SizeOfInt..];
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

	public virtual void GetHash(Span<byte> destination)
	{
		try
		{
			const uint padding = 0b10000000;
			X[_index++] = _bufferIndex switch
			{
				0 => padding,
				1 => _buffer[0] | padding << 8,
				2 => _buffer[0] | (uint)_buffer[1] << 8 | padding << 16,
				3 => _buffer[0] | (uint)_buffer[1] << 8 | (uint)_buffer[2] << 16 | padding << 24,
				_ => throw new InvalidOperationException(@"unreachable code!!!")
			};

			if (_index == 15)
			{
				X[15] = 0;
			}

			if (_index > 14) // 15 or 16
			{
				Process();
				_index = 0;
			}

			//final

			for (var i = _index; i < 14; ++i)
			{
				X[i] = 0;
			}

			X[14] = (uint)(_byteCount << 3 & 0xFFFFFFFF);
			X[15] = (uint)(_byteCount >> (32 - 3) & 0xFFFFFFFF);

			Process();

			BinaryPrimitives.WriteUInt32LittleEndian(destination, A);
			BinaryPrimitives.WriteUInt32LittleEndian(destination[4..], B);
			BinaryPrimitives.WriteUInt32LittleEndian(destination[8..], C);
			BinaryPrimitives.WriteUInt32LittleEndian(destination[12..], D);
		}
		finally
		{
			Reset();
		}
	}

	public void Reset()
	{
		A = 0x67452301;
		B = 0xefcdab89;
		C = 0x98badcfe;
		D = 0x10325476;
		_byteCount = 0;
		_index = 0;
		_bufferIndex = 0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	protected void Process()
	{
		var a = A;
		var b = B;
		var c = C;
		var d = D;

		a = FF(a, b, c, d, X[0], S11, 3614090360);
		d = FF(d, a, b, c, X[1], S12, 3905402710);
		c = FF(c, d, a, b, X[2], S13, 606105819);
		b = FF(b, c, d, a, X[3], S14, 3250441966);
		a = FF(a, b, c, d, X[4], S11, 4118548399);
		d = FF(d, a, b, c, X[5], S12, 1200080426);
		c = FF(c, d, a, b, X[6], S13, 2821735955);
		b = FF(b, c, d, a, X[7], S14, 4249261313);
		a = FF(a, b, c, d, X[8], S11, 1770035416);
		d = FF(d, a, b, c, X[9], S12, 2336552879);
		c = FF(c, d, a, b, X[10], S13, 4294925233);
		b = FF(b, c, d, a, X[11], S14, 2304563134);
		a = FF(a, b, c, d, X[12], S11, 1804603682);
		d = FF(d, a, b, c, X[13], S12, 4254626195);
		c = FF(c, d, a, b, X[14], S13, 2792965006);
		b = FF(b, c, d, a, X[15], S14, 1236535329);

		a = GG(a, b, c, d, X[1], S21, 4129170786);
		d = GG(d, a, b, c, X[6], S22, 3225465664);
		c = GG(c, d, a, b, X[11], S23, 643717713);
		b = GG(b, c, d, a, X[0], S24, 3921069994);
		a = GG(a, b, c, d, X[5], S21, 3593408605);
		d = GG(d, a, b, c, X[10], S22, 38016083);
		c = GG(c, d, a, b, X[15], S23, 3634488961);
		b = GG(b, c, d, a, X[4], S24, 3889429448);
		a = GG(a, b, c, d, X[9], S21, 568446438);
		d = GG(d, a, b, c, X[14], S22, 3275163606);
		c = GG(c, d, a, b, X[3], S23, 4107603335);
		b = GG(b, c, d, a, X[8], S24, 1163531501);
		a = GG(a, b, c, d, X[13], S21, 2850285829);
		d = GG(d, a, b, c, X[2], S22, 4243563512);
		c = GG(c, d, a, b, X[7], S23, 1735328473);
		b = GG(b, c, d, a, X[12], S24, 2368359562);

		a = HH(a, b, c, d, X[5], S31, 4294588738);
		d = HH(d, a, b, c, X[8], S32, 2272392833);
		c = HH(c, d, a, b, X[11], S33, 1839030562);
		b = HH(b, c, d, a, X[14], S34, 4259657740);
		a = HH(a, b, c, d, X[1], S31, 2763975236);
		d = HH(d, a, b, c, X[4], S32, 1272893353);
		c = HH(c, d, a, b, X[7], S33, 4139469664);
		b = HH(b, c, d, a, X[10], S34, 3200236656);
		a = HH(a, b, c, d, X[13], S31, 681279174);
		d = HH(d, a, b, c, X[0], S32, 3936430074);
		c = HH(c, d, a, b, X[3], S33, 3572445317);
		b = HH(b, c, d, a, X[6], S34, 76029189);
		a = HH(a, b, c, d, X[9], S31, 3654602809);
		d = HH(d, a, b, c, X[12], S32, 3873151461);
		c = HH(c, d, a, b, X[15], S33, 530742520);
		b = HH(b, c, d, a, X[2], S34, 3299628645);

		a = II(a, b, c, d, X[0], S41, 4096336452);
		d = II(d, a, b, c, X[7], S42, 1126891415);
		c = II(c, d, a, b, X[14], S43, 2878612391);
		b = II(b, c, d, a, X[5], S44, 4237533241);
		a = II(a, b, c, d, X[12], S41, 1700485571);
		d = II(d, a, b, c, X[3], S42, 2399980690);
		c = II(c, d, a, b, X[10], S43, 4293915773);
		b = II(b, c, d, a, X[1], S44, 2240044497);
		a = II(a, b, c, d, X[8], S41, 1873313359);
		d = II(d, a, b, c, X[15], S42, 4264355552);
		c = II(c, d, a, b, X[6], S43, 2734768916);
		b = II(b, c, d, a, X[13], S44, 1309151649);
		a = II(a, b, c, d, X[4], S41, 4149444226);
		d = II(d, a, b, c, X[11], S42, 3174756917);
		c = II(c, d, a, b, X[2], S43, 718787259);
		b = II(b, c, d, a, X[9], S44, 3951481745);

		A += a;
		B += b;
		C += c;
		D += d;
	}

	public void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
