using CryptoBase.Abstractions.Digests;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Digests.SM3
{
	/// <summary>
	/// https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
	/// </summary>
	public class SM3Digest : IHash
	{
		private const int BlockSizeOfInt = 16;
		private const int SizeOfInt = sizeof(uint);

		private static readonly uint[] T = new uint[64];

		private static readonly Vector256<uint> Init = Vector256.Create(0x7380166FU, 0x4914B2B9U, 0x172442D7U, 0xDA8A0600U, 0xA96F30BCU, 0x163138AAU, 0xE38DEE4DU, 0xB0FB0E4EU);

		private Vector256<uint> V;
		private ulong _byteCount;
		private int _index;
		private int _bufferIndex;

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
			//return (x & y) | IntrinsicsUtils.AndNot(x, z);
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
			for (var i = 0; i < 16; ++i)
			{
				T[i] = 0x79CC4519U.RotateLeft(i);
			}

			for (var i = 16; i < 64; ++i)
			{
				T[i] = 0x7A879D8AU.RotateLeft(i);
			}
		}

		public SM3Digest()
		{
			_w = new uint[68];
			_buffer = new byte[SizeOfInt];
			Reset();
		}

		public string Name => @"SM3";

		public int Length => HashConstants.SM3Length;

		public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Update(origin);
			GetHash(destination);
		}

		public void Update(ReadOnlySpan<byte> source)
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

				source.Slice(0, remain).CopyTo(_buffer.AsSpan(_bufferIndex));
				source = source.Slice(remain);
				_w[_index++] = BinaryPrimitives.ReadUInt32BigEndian(_buffer);
				_bufferIndex = 0;
			}

			while (source.Length >= SizeOfInt)
			{
				if (_index == BlockSizeOfInt)
				{
					Process();
					_index = 0;
				}

				_w[_index++] = BinaryPrimitives.ReadUInt32BigEndian(source);
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

		public unsafe void GetHash(Span<byte> destination)
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
					_ => throw new InvalidOperationException(@"unreachable code!!!")
				};

				if (_index == 15)
				{
					_w[15] = 0;
				}

				if (_index > 14) // 15 or 16
				{
					Process();
					_index = 0;
				}

				for (var i = _index; i < 14; ++i)
				{
					_w[i] = 0;
				}

				_w[14] = (uint)(_byteCount >> (32 - 3) & 0xFFFFFFFF);
				_w[15] = (uint)(_byteCount << 3 & 0xFFFFFFFF);

				Process();

				if (Avx.IsSupported)
				{
					var v = V.ReverseEndianness32();
					fixed (byte* p = destination)
					{
						Avx.Store(p, v);
					}
				}
				else
				{
					BinaryPrimitives.WriteUInt32BigEndian(destination, V.GetElement(0));
					BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), V.GetElement(1));
					BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8), V.GetElement(2));
					BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(12), V.GetElement(3));
					BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(16), V.GetElement(4));
					BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(20), V.GetElement(5));
					BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(24), V.GetElement(6));
					BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(28), V.GetElement(7));
				}
			}
			finally
			{
				Reset();
			}
		}

		public void Reset()
		{
			V = Init;
			_byteCount = 0;
			_index = 0;
			_bufferIndex = 0;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void Process()
		{
			for (var j = 16; j < 68; ++j)
			{
				_w[j] = P1(_w[j - 16] ^ _w[j - 9] ^ _w[j - 3].RotateLeft(15)) ^ _w[j - 13].RotateLeft(7) ^ _w[j - 6];
			}

			var a = V.GetElement(0);
			var b = V.GetElement(1);
			var c = V.GetElement(2);
			var d = V.GetElement(3);
			var e = V.GetElement(4);
			var f = V.GetElement(5);
			var g = V.GetElement(6);
			var h = V.GetElement(7);

			for (var j = 0; j < 64; ++j)
			{
				var a12 = a.RotateLeft(12);
				var ss1 = (a12 + e + T[j]).RotateLeft(7);
				var ss2 = ss1 ^ a12;

				var w1 = _w[j] ^ _w[j + 4];
				uint tt1, tt2;
				if (j < 16)
				{
					tt1 = FF0(a, b, c) + d + ss2 + w1;
					tt2 = GG0(e, f, g) + h + ss1 + _w[j];
				}
				else
				{
					tt1 = FF1(a, b, c) + d + ss2 + w1;
					tt2 = GG1(e, f, g) + h + ss1 + _w[j];
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

			if (Avx2.IsSupported)
			{
				var t = Vector256.Create(a, b, c, d, e, f, g, h);
				V = Avx2.Xor(V, t);
			}
			else
			{
				V = Vector256.Create(
					V.GetElement(0) ^ a,
					V.GetElement(1) ^ b,
					V.GetElement(2) ^ c,
					V.GetElement(3) ^ d,
					V.GetElement(4) ^ e,
					V.GetElement(5) ^ f,
					V.GetElement(6) ^ g,
					V.GetElement(7) ^ h);
			}
		}
	}
}
