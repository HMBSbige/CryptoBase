using System;
using System.Buffers;
using System.Buffers.Binary;

namespace CryptoBase.Macs.GHash
{
	public class GHashSF : GHash
	{
		private static readonly ulong[] Last4 =
		{
			0x0000, 0x1c20, 0x3840, 0x2460,
			0x7080, 0x6ca0, 0x48c0, 0x54e0,
			0xe100, 0xfd20, 0xd940, 0xc560,
			0x9180, 0x8da0, 0xa9c0, 0xb5e0
		};

		private readonly ulong[] _hh;
		private readonly ulong[] _hl;
		private readonly byte[] _buffer;

		private readonly ReadOnlyMemory<byte> _key;

		public GHashSF(byte[] key) : base(key)
		{
			_key = key;

			_hl = ArrayPool<ulong>.Shared.Rent(BlockSize);
			_hh = ArrayPool<ulong>.Shared.Rent(BlockSize);
			_buffer = ArrayPool<byte>.Shared.Rent(BlockSize);

			Reset();
		}

		protected override void GFMul(ReadOnlySpan<byte> x)
		{
			for (var i = 0; i < BlockSize; ++i)
			{
				_buffer[i] ^= x[i];
			}

			var lo = (byte)(_buffer[15] & 0xF);
			var zh = _hh[lo];
			var zl = _hl[lo];

			for (var i = 0; i < BlockSize; ++i)
			{
				lo = (byte)(_buffer[16 - 1 - i] & 0xf);
				var hi = (byte)((_buffer[16 - 1 - i] >> 4) & 0xf);

				byte rem;
				if (i != 0)
				{
					rem = (byte)(zl & 0xf);
					zl = (zh << 60) | (zl >> 4);
					zh >>= 4;
					zh ^= Last4[rem] << 48;
					zh ^= _hh[lo];
					zl ^= _hl[lo];
				}

				rem = (byte)(zl & 0xf);
				zl = (zh << 60) | (zl >> 4);
				zh >>= 4;

				zh ^= Last4[rem] << 48;
				zh ^= _hh[hi];
				zl ^= _hl[hi];
			}

			BinaryPrimitives.WriteUInt64BigEndian(_buffer, zh);
			BinaryPrimitives.WriteUInt64BigEndian(_buffer.AsSpan(8), zl);
		}

		public override void GetMac(Span<byte> destination)
		{
			_buffer.AsSpan(0, TagSize).CopyTo(destination);

			Reset();
		}

		public sealed override void Reset()
		{
			_buffer.AsSpan(0, BlockSize).Clear();

			var vh = BinaryPrimitives.ReadUInt64BigEndian(_key.Span);
			var vl = BinaryPrimitives.ReadUInt64BigEndian(_key.Span.Slice(8));

			_hl[8] = vl;
			_hh[8] = vh;

			var i = 4u;

			while (i > 0)
			{
				var t = (vl & 1) * 0xe1000000;
				vl = (vh << 63) | (vl >> 1);
				vh = (vh >> 1) ^ (t << 32);

				_hl[i] = vl;
				_hh[i] = vh;

				i >>= 1;
			}

			i = 2u;
			while (i <= 8)
			{
				vh = _hh[i];
				vl = _hl[i];

				for (var j = 1u; j < i; ++j)
				{
					_hh[i + j] = vh ^ _hh[j];
					_hl[i + j] = vl ^ _hl[j];
				}

				i <<= 1;
			}
		}

		public override void Dispose()
		{
			base.Dispose();

			ArrayPool<ulong>.Shared.Return(_hl);
			ArrayPool<ulong>.Shared.Return(_hh);
			ArrayPool<byte>.Shared.Return(_buffer);
		}
	}
}
