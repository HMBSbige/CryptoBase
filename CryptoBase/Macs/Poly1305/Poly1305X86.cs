using CryptoBase.Abstractions;
using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Macs.Poly1305
{
	public class Poly1305X86 : IMac, IIntrinsics
	{
		public bool IsSupport => Poly1305Utils.IsSupportX86;

		public string Name => @"Poly1305";

		public const int KeySize = 32;
		public const int BlockSize = 16;
		public const int BlockSize2 = BlockSize * 2;
		public const int TagSize = 16;

		private readonly uint _x0, _x1, _x2, _x3;
		private uint _h0, _h1, _h2, _h3, _h4;

		private readonly Vector128<uint> _r0s4, _s3s2, _r1r0, _s4s3, _s1s2, _r2r1, _r3r2, _s3s4, _r4r3, _r0;

		private readonly Vector128<uint> _ru0, _ru1, _ru2, _ru3, _ru4;
		private readonly Vector128<uint> _sv1, _sv2, _sv3, _sv4;

		public Poly1305X86(ReadOnlySpan<byte> key)
		{
			if (key.Length < KeySize)
			{
				throw new ArgumentException(@"Key length must be 32 bytes", nameof(key));
			}

			// r &= 0xFFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
			var r0 = BinaryPrimitives.ReadUInt32LittleEndian(key) & 0x3FFFFFF;
			var r1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(3)) >> 2 & 0x3FFFF03;
			var r2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(6)) >> 4 & 0x3FFC0FF;
			var r3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(9)) >> 6 & 0x3F03FFF;
			var r4 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12)) >> 8 & 0x00FFFFF;

			var s1 = r1 * 5;
			var s2 = r2 * 5;
			var s3 = r3 * 5;
			var s4 = r4 * 5;

			_r0s4 = IntrinsicsUtils.CreateTwoUInt(r0, s4);
			_s3s2 = IntrinsicsUtils.CreateTwoUInt(s3, s2);
			_r1r0 = IntrinsicsUtils.CreateTwoUInt(r1, r0);
			_s4s3 = IntrinsicsUtils.CreateTwoUInt(s4, s3);
			_s1s2 = IntrinsicsUtils.CreateTwoUInt(s1, s2);
			_r2r1 = IntrinsicsUtils.CreateTwoUInt(r2, r1);
			_r3r2 = IntrinsicsUtils.CreateTwoUInt(r3, r2);
			_s3s4 = IntrinsicsUtils.CreateTwoUInt(s3, s4);
			_r4r3 = IntrinsicsUtils.CreateTwoUInt(r4, r3);
			_r0 = Sse2.ConvertScalarToVector128UInt32(r0);

			_x0 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16));
			_x1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20));
			_x2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24));
			_x3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28));

			var u0 = r0;
			var u1 = r1;
			var u2 = r2;
			var u3 = r3;
			var u4 = r4;
			MultiplyR(ref u0, ref u1, ref u2, ref u3, ref u4);

			_ru0 = IntrinsicsUtils.CreateTwoUInt(u0, r0);
			_ru1 = IntrinsicsUtils.CreateTwoUInt(u1, r1);
			_ru2 = IntrinsicsUtils.CreateTwoUInt(u2, r2);
			_ru3 = IntrinsicsUtils.CreateTwoUInt(u3, r3);
			_ru4 = IntrinsicsUtils.CreateTwoUInt(u4, r4);

			_sv1 = Multiply5(ref _ru1);
			_sv2 = Multiply5(ref _ru2);
			_sv3 = Multiply5(ref _ru3);
			_sv4 = Multiply5(ref _ru4);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private static Vector128<uint> Multiply5(ref Vector128<uint> a)
		{
			var t = Sse2.ShiftLeftLogical(a, 2);
			return Sse2.Add(t, a);
		}

		/// <summary>
		///  a *= r
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private void MultiplyR(ref uint a0, ref uint a1, ref uint a2, ref uint a3, ref uint a4)
		{
			var h01 = IntrinsicsUtils.CreateTwoUInt(a0, a1);
			var h23 = IntrinsicsUtils.CreateTwoUInt(a2, a3);
			var h44 = IntrinsicsUtils.CreateTwoUInt(a4, a4);

			MultiplyR(ref h01, ref h23, ref h44, out var d0, out var d1, out var d2, out var d3, out var d4);

			a0 = (uint)d0 & 0x3ffffff;
			d1 += (uint)(d0 >> 26);
			a1 = (uint)d1 & 0x3ffffff;
			d2 += (uint)(d1 >> 26);
			a2 = (uint)d2 & 0x3ffffff;
			d3 += (uint)(d2 >> 26);
			a3 = (uint)d3 & 0x3ffffff;
			d4 += (uint)(d3 >> 26);
			a4 = (uint)d4 & 0x3ffffff;
			a0 += (uint)(d4 >> 26) * 5;
			a1 += a0 >> 26;
			a0 &= 0x3ffffff;
		}

		/// <summary>
		/// d = h * r
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveOptimization)]
		private void MultiplyR(
			ref Vector128<uint> h01, ref Vector128<uint> h23, ref Vector128<uint> h44,
			out ulong d0, out ulong d1, out ulong d2, out ulong d3, out ulong d4)
		{
			// h0 * r0 + h2 * s3
			// h1 * s4 + h3 * s2
			var t00 = Sse2.Multiply(h01, _r0s4);
			var t01 = Sse2.Multiply(h23, _s3s2);
			var t1 = Sse2.Add(t01, t00);
			// h0 * r1 + h2 * s4
			// h1 * r0 + h3 * s3
			t00 = Sse2.Multiply(h01, _r1r0);
			t01 = Sse2.Multiply(h23, _s4s3);
			var t2 = Sse2.Add(t01, t00);
			// h4 * s1
			// h4 * s2
			var t3 = Sse2.Multiply(h44, _s1s2);
			// d0 = t1[0] + t1[1] + t3[0]
			// d1 = t2[0] + t2[1] + t3[1]
			var t = Sse2.UnpackLow(t1, t2).Add(Sse2.UnpackHigh(t1, t2)).Add(t3);
			d0 = t.ToScalar();
			d1 = Sse2.ShiftRightLogical128BitLane(t, 8).ToScalar();

			// h0 * r2 + h2 * r0
			// h1 * r1 + h3 * s4
			t00 = Sse2.Multiply(h01, _r2r1);
			t01 = Sse2.Multiply(h23, _r0s4);
			t1 = Sse2.Add(t01, t00);
			// h0 * r3 + h2 * r1
			// h1 * r2 + h3 * r0
			t00 = Sse2.Multiply(h01, _r3r2);
			t01 = Sse2.Multiply(h23, _r1r0);
			t2 = Sse2.Add(t01, t00);
			// h4 * s3
			// h4 * s4
			t3 = Sse2.Multiply(h44, _s3s4);
			// d2 = t1[0] + t1[1] + t3[0]
			// d3 = t2[0] + t2[1] + t3[1]
			t = Sse2.UnpackLow(t1, t2).Add(Sse2.UnpackHigh(t1, t2)).Add(t3);
			d2 = t.ToScalar();
			d3 = Sse2.ShiftRightLogical128BitLane(t, 8).ToScalar();

			// h0 * r4 + h2 * r2
			// h1 * r3 + h3 * r1
			t00 = Sse2.Multiply(h01, _r4r3);
			t01 = Sse2.Multiply(h23, _r2r1);
			t1 = Sse2.Add(t01, t00);
			// h4 * r0
			t3 = Sse2.Multiply(h44, _r0);
			// d4 = t1[0] + t1[1] + t3[0]
			d4 = t1.Add(Sse2.ShiftRightLogical128BitLane(t1, 8)).Add(t3).ToScalar();
		}

		/// <summary>
		/// h += m
		/// h *= r
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private void Block(ReadOnlySpan<byte> m)
		{
			var h01 = IntrinsicsUtils.CreateTwoUInt(_h0, _h1);
			var h23 = IntrinsicsUtils.CreateTwoUInt(_h2, _h3);
			var h44 = IntrinsicsUtils.CreateTwoUInt(_h4, _h4);

			var m06 = IntrinsicsUtils.CreateTwoUInt(BinaryPrimitives.ReadUInt32LittleEndian(m) & 0x3ffffff, BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(3)) >> 2 & 0x3ffffff);
			h01 = Sse2.Add(h01, m06);
			var m612 = IntrinsicsUtils.CreateTwoUInt(BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(6)) >> 4 & 0x3ffffff, BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(9)) >> 6 & 0x3ffffff);
			h23 = Sse2.Add(h23, m612);
			var m4 = BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(12)) >> 8 | 1u << 24;
			h44 = Sse2.Add(h44, IntrinsicsUtils.CreateTwoUInt(m4));

			MultiplyR(ref h01, ref h23, ref h44, out var d0, out var d1, out var d2, out var d3, out var d4);

			_h0 = (uint)d0 & 0x3ffffff;
			d1 += (uint)(d0 >> 26);
			_h1 = (uint)d1 & 0x3ffffff;
			d2 += (uint)(d1 >> 26);
			_h2 = (uint)d2 & 0x3ffffff;
			d3 += (uint)(d2 >> 26);
			_h3 = (uint)d3 & 0x3ffffff;
			d4 += (uint)(d3 >> 26);
			_h4 = (uint)d4 & 0x3ffffff;
			_h0 += (uint)(d4 >> 26) * 5;
			_h1 += _h0 >> 26;
			_h0 &= 0x3ffffff;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private void Block2(ReadOnlySpan<byte> m)
		{
			var hc0 = IntrinsicsUtils.CreateTwoUInt(_h0 + (BinaryPrimitives.ReadUInt32LittleEndian(m) & 0x3ffffff), BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(16)) & 0x3ffffff);
			var hc1 = IntrinsicsUtils.CreateTwoUInt(_h1 + (BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(3)) >> 2 & 0x3ffffff), BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(19)) >> 2 & 0x3ffffff);
			var hc2 = IntrinsicsUtils.CreateTwoUInt(_h2 + (BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(6)) >> 4 & 0x3ffffff), BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(22)) >> 4 & 0x3ffffff);
			var hc3 = IntrinsicsUtils.CreateTwoUInt(_h3 + (BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(9)) >> 6 & 0x3ffffff), BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(25)) >> 6 & 0x3ffffff);
			var hc4 = IntrinsicsUtils.CreateTwoUInt(_h4 + (BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(12)) >> 8 | 1u << 24), BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(28)) >> 8 | 1u << 24);

			var t1 = Sse2.Multiply(_ru0, hc0);
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv4, hc1));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv3, hc2));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv2, hc3));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv1, hc4));
			var d0 = t1.ToScalar() + Sse2.ShiftRightLogical128BitLane(t1, 8).ToScalar();

			t1 = Sse2.Multiply(_ru1, hc0);
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru0, hc1));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv4, hc2));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv3, hc3));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv2, hc4));
			var d1 = t1.ToScalar() + Sse2.ShiftRightLogical128BitLane(t1, 8).ToScalar();

			t1 = Sse2.Multiply(_ru2, hc0);
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru1, hc1));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru0, hc2));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv4, hc3));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv3, hc4));
			var d2 = t1.ToScalar() + Sse2.ShiftRightLogical128BitLane(t1, 8).ToScalar();

			t1 = Sse2.Multiply(_ru3, hc0);
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru2, hc1));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru1, hc2));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru0, hc3));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv4, hc4));
			var d3 = t1.ToScalar() + Sse2.ShiftRightLogical128BitLane(t1, 8).ToScalar();

			t1 = Sse2.Multiply(_ru4, hc0);
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru3, hc1));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru2, hc2));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru1, hc3));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru0, hc4));
			var d4 = t1.ToScalar() + Sse2.ShiftRightLogical128BitLane(t1, 8).ToScalar();

			_h0 = (uint)d0 & 0x3ffffff;
			d1 += (uint)(d0 >> 26);
			_h1 = (uint)d1 & 0x3ffffff;
			d2 += (uint)(d1 >> 26);
			_h2 = (uint)d2 & 0x3ffffff;
			d3 += (uint)(d2 >> 26);
			_h3 = (uint)d3 & 0x3ffffff;
			d4 += (uint)(d3 >> 26);
			_h4 = (uint)d4 & 0x3ffffff;
			_h0 += (uint)(d4 >> 26) * 5;
			_h1 += _h0 >> 26;
			_h0 &= 0x3ffffff;
		}

		public void Update(ReadOnlySpan<byte> source)
		{
			while (source.Length >= BlockSize2)
			{
				Block2(source);
				source = source.Slice(BlockSize2);
			}

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
