using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace CryptoBase.Macs.Poly1305
{
	public class Poly1305SF : IMac
	{
		public string Name => @"Poly1305";

		public const int KeySize = 32;
		public const int BlockSize = 16;
		public const int TagSize = 16;

		private readonly uint _r0, _r1, _r2, _r3, _r4;
		private readonly uint _s1, _s2, _s3, _s4;
		private readonly uint _x0, _x1, _x2, _x3;

		private uint _h0, _h1, _h2, _h3, _h4;

		public Poly1305SF(ReadOnlySpan<byte> key)
		{
			if (key.Length < KeySize)
			{
				throw new ArgumentException(@"Key length must be 32 bytes", nameof(key));
			}

			// Init

			// r &= 0xFFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
			_r0 = BinaryPrimitives.ReadUInt32LittleEndian(key) & 0x3FFFFFF;
			_r1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(3)) >> 2 & 0x3FFFF03;
			_r2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(6)) >> 4 & 0x3FFC0FF;
			_r3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(9)) >> 6 & 0x3F03FFF;
			_r4 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12)) >> 8 & 0x00FFFFF;

			_s1 = _r1 * 5;
			_s2 = _r2 * 5;
			_s3 = _r3 * 5;
			_s4 = _r4 * 5;

			_x0 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16));
			_x1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20));
			_x2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24));
			_x3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private void Block(ReadOnlySpan<byte> m)
		{
			_h0 += BinaryPrimitives.ReadUInt32LittleEndian(m) & 0x3ffffff;
			_h1 += BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(3)) >> 2 & 0x3ffffff;
			_h2 += BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(6)) >> 4 & 0x3ffffff;
			_h3 += BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(9)) >> 6 & 0x3ffffff;
			_h4 += BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(12)) >> 8 | 1u << 24;

			var p0 = (ulong)_h0 * _r0 + (ulong)_h1 * _s4 + (ulong)_h2 * _s3 + (ulong)_h3 * _s2 + (ulong)_h4 * _s1;
			var p1 = (ulong)_h0 * _r1 + (ulong)_h1 * _r0 + (ulong)_h2 * _s4 + (ulong)_h3 * _s3 + (ulong)_h4 * _s2;
			var p2 = (ulong)_h0 * _r2 + (ulong)_h1 * _r1 + (ulong)_h2 * _r0 + (ulong)_h3 * _s4 + (ulong)_h4 * _s3;
			var p3 = (ulong)_h0 * _r3 + (ulong)_h1 * _r2 + (ulong)_h2 * _r1 + (ulong)_h3 * _r0 + (ulong)_h4 * _s4;
			var p4 = (ulong)_h0 * _r4 + (ulong)_h1 * _r3 + (ulong)_h2 * _r2 + (ulong)_h3 * _r1 + (ulong)_h4 * _r0;

			_h0 = (uint)p0 & 0x3ffffff;
			p1 += (uint)(p0 >> 26);
			_h1 = (uint)p1 & 0x3ffffff;
			p2 += (uint)(p1 >> 26);
			_h2 = (uint)p2 & 0x3ffffff;
			p3 += (uint)(p2 >> 26);
			_h3 = (uint)p3 & 0x3ffffff;
			p4 += (uint)(p3 >> 26);
			_h4 = (uint)p4 & 0x3ffffff;
			_h0 += (uint)(p4 >> 26) * 5;
			_h1 += _h0 >> 26;
			_h0 &= 0x3ffffff;
		}

		[MethodImpl(MethodImplOptions.AggressiveOptimization)]
		public void Update(ReadOnlySpan<byte> source)
		{
			while (source.Length >= BlockSize)
			{
				Block(source);
				source = source.Slice(BlockSize);
			}

			if (source.IsEmpty)
			{
				return;
			}

			Span<byte> block = stackalloc byte[BlockSize];
			source.CopyTo(block);

			Block(block);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public void GetMac(Span<byte> destination)
		{
			_h2 += _h1 >> 26;
			_h1 &= 0x3ffffff;
			_h3 += _h2 >> 26;
			_h2 &= 0x3ffffff;
			_h4 += _h3 >> 26;
			_h3 &= 0x3ffffff;
			_h0 += (_h4 >> 26) * 5;
			_h4 &= 0x3ffffff;
			_h1 += _h0 >> 26;
			_h0 &= 0x3ffffff;

			var g0 = _h0 + 5;
			var g1 = _h1 + (g0 >> 26);
			g0 &= 0x3ffffff;
			var g2 = _h2 + (g1 >> 26);
			g1 &= 0x3ffffff;
			var g3 = _h3 + (g2 >> 26);
			g2 &= 0x3ffffff;
			var g4 = _h4 + (g3 >> 26) - (1u << 26);
			g3 &= 0x3ffffff;

			var mask = (g4 >> 31) - 1;
			g0 &= mask;
			g1 &= mask;
			g2 &= mask;
			g3 &= mask;
			g4 &= mask;
			mask = ~mask;
			_h0 = _h0 & mask | g0;
			_h1 = _h1 & mask | g1;
			_h2 = _h2 & mask | g2;
			_h3 = _h3 & mask | g3;
			_h4 = _h4 & mask | g4;

			var f0 = (_h0 | _h1 << 26) + (ulong)_x0;
			var f1 = (_h1 >> 6 | _h2 << 20) + (ulong)_x1;
			var f2 = (_h2 >> 12 | _h3 << 14) + (ulong)_x2;
			var f3 = (_h3 >> 18 | _h4 << 8) + (ulong)_x3;

			f1 += f0 >> 32;
			f2 += f1 >> 32;
			f3 += f2 >> 32;

			BinaryPrimitives.WriteUInt32LittleEndian(destination, (uint)f0);
			BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(4), (uint)f1);
			BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(8), (uint)f2);
			BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(12), (uint)f3);

			Reset();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public void Reset()
		{
			_h0 = _h1 = _h2 = _h3 = _h4 = 0;
		}

		public void Dispose() { }
	}
}
