using CryptoBase.Abstractions;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.Macs.Poly1305
{
	public class Poly1305X86 : IMac
	{
		public string Name => @"Poly1305";

		public int Length => 16;

		public const int KeySize = 32;
		public const int BlockSize = 16;
		public const int BlockSize2 = BlockSize * 2;
		public const int BlockSize4 = BlockSize * 4;

		private static readonly Vector128<uint> And128 = Vector128.Create(0x3ffffff, 0, 0x3ffffff, 0).AsUInt32();
		private static readonly Vector128<uint> Or128 = Vector128.Create(0x01000000, 0, 0x01000000, 0).AsUInt32();
		private static readonly Vector256<uint> And256 = Vector256.Create(0x3ffffff, 0, 0x3ffffff, 0, 0x3ffffff, 0, 0x3ffffff, 0).AsUInt32();
		private static readonly Vector256<uint> Or256 = Vector256.Create(0x01000000, 0, 0x01000000, 0, 0x01000000, 0, 0x01000000, 0).AsUInt32();

		private readonly uint _x0, _x1, _x2, _x3;
		private uint _h0, _h1, _h2, _h3, _h4;

		private readonly Vector128<uint> _r0s4, _s3s2, _r1r0, _s4s3, _s1s2, _r2r1, _r3r2, _s3s4, _r4r3, _r0;

		private readonly Vector128<uint> _ru0, _ru1, _ru2, _ru3, _ru4;
		private readonly Vector128<uint> _sv1, _sv2, _sv3, _sv4;

		private readonly Vector256<uint> _ruwy0, _ruwy1, _ruwy2, _ruwy3, _ruwy4;
		private readonly Vector256<uint> _svxz1, _svxz2, _svxz3, _svxz4;

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

			_sv1 = _ru1.Multiply5();
			_sv2 = _ru2.Multiply5();
			_sv3 = _ru3.Multiply5();
			_sv4 = _ru4.Multiply5();

			if (Avx2.IsSupported)
			{
				var w0 = u0;
				var w1 = u1;
				var w2 = u2;
				var w3 = u3;
				var w4 = u4;
				MultiplyR(ref w0, ref w1, ref w2, ref w3, ref w4);

				var y0 = w0;
				var y1 = w1;
				var y2 = w2;
				var y3 = w3;
				var y4 = w4;
				MultiplyR(ref y0, ref y1, ref y2, ref y3, ref y4);

				_ruwy0 = IntrinsicsUtils.Create4UInt(y0, w0, u0, r0);
				_ruwy1 = IntrinsicsUtils.Create4UInt(y1, w1, u1, r1);
				_ruwy2 = IntrinsicsUtils.Create4UInt(y2, w2, u2, r2);
				_ruwy3 = IntrinsicsUtils.Create4UInt(y3, w3, u3, r3);
				_ruwy4 = IntrinsicsUtils.Create4UInt(y4, w4, u4, r4);

				_svxz1 = _ruwy1.Multiply5();
				_svxz2 = _ruwy2.Multiply5();
				_svxz3 = _ruwy3.Multiply5();
				_svxz4 = _ruwy4.Multiply5();
			}
		}

		/// <summary>
		///  a *= r
		/// </summary>
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

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void Block2(ReadOnlySpan<byte> m)
		{
			var n0 = MemoryMarshal.Cast<byte, uint>(m);
			var hc0 = IntrinsicsUtils.CreateTwoUInt(n0[0], n0[4]);
			hc0 = Sse2.And(hc0, And128);
			hc0 = Sse2.Add(hc0, Sse2.ConvertScalarToVector128UInt32(_h0));

			var n1 = MemoryMarshal.Cast<byte, uint>(m.Slice(3));
			var hc1 = IntrinsicsUtils.CreateTwoUInt(n1[0], n1[4]);
			hc1 = Sse2.ShiftRightLogical(hc1, 2);
			hc1 = Sse2.And(hc1, And128);
			hc1 = Sse2.Add(hc1, Sse2.ConvertScalarToVector128UInt32(_h1));

			var n2 = MemoryMarshal.Cast<byte, uint>(m.Slice(6));
			var hc2 = IntrinsicsUtils.CreateTwoUInt(n2[0], n2[4]);
			hc2 = Sse2.ShiftRightLogical(hc2, 4);
			hc2 = Sse2.And(hc2, And128);
			hc2 = Sse2.Add(hc2, Sse2.ConvertScalarToVector128UInt32(_h2));

			var n3 = MemoryMarshal.Cast<byte, uint>(m.Slice(9));
			var hc3 = IntrinsicsUtils.CreateTwoUInt(n3[0], n3[4]);
			hc3 = Sse2.ShiftRightLogical(hc3, 6);
			hc3 = Sse2.And(hc3, And128);
			hc3 = Sse2.Add(hc3, Sse2.ConvertScalarToVector128UInt32(_h3));

			var n4 = MemoryMarshal.Cast<byte, uint>(m.Slice(12));
			var hc4 = IntrinsicsUtils.CreateTwoUInt(n4[0], n4[4]);
			hc4 = Sse2.ShiftRightLogical(hc4, 8);
			hc4 = Sse2.Xor(hc4, Or128);
			hc4 = Sse2.Add(hc4, Sse2.ConvertScalarToVector128UInt32(_h4));

			var t1 = Sse2.Multiply(_ru0, hc0);
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv4, hc1));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv3, hc2));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv2, hc3));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv1, hc4));
			var d0 = t1.Add2UInt64();

			t1 = Sse2.Multiply(_ru1, hc0);
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru0, hc1));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv4, hc2));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv3, hc3));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv2, hc4));
			var d1 = t1.Add2UInt64();

			t1 = Sse2.Multiply(_ru2, hc0);
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru1, hc1));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru0, hc2));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv4, hc3));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv3, hc4));
			var d2 = t1.Add2UInt64();

			t1 = Sse2.Multiply(_ru3, hc0);
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru2, hc1));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru1, hc2));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru0, hc3));
			t1 = Sse2.Add(t1, Sse2.Multiply(_sv4, hc4));
			var d3 = t1.Add2UInt64();

			t1 = Sse2.Multiply(_ru4, hc0);
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru3, hc1));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru2, hc2));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru1, hc3));
			t1 = Sse2.Add(t1, Sse2.Multiply(_ru0, hc4));
			var d4 = t1.Add2UInt64();

			_h0 = (uint)d0 & 0x3ffffff;
			d1 += d0 >> 26;
			_h1 = (uint)d1 & 0x3ffffff;
			d2 += d1 >> 26;
			_h2 = (uint)d2 & 0x3ffffff;
			d3 += d2 >> 26;
			_h3 = (uint)d3 & 0x3ffffff;
			d4 += d3 >> 26;
			_h4 = (uint)d4 & 0x3ffffff;
			_h0 += (uint)((d4 >> 26) * 5);
			_h1 += _h0 >> 26;
			_h0 &= 0x3ffffff;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void Block4(ReadOnlySpan<byte> m)
		{
			var n0 = MemoryMarshal.Cast<byte, uint>(m);
			var hc0 = IntrinsicsUtils.Create4UInt(n0[0], n0[4], n0[8], n0[12]);
			hc0 = Avx2.And(hc0, And256);
			hc0 = Avx2.Add(hc0, Vector256.CreateScalar(_h0));

			var n1 = MemoryMarshal.Cast<byte, uint>(m.Slice(3));
			var hc1 = IntrinsicsUtils.Create4UInt(n1[0], n1[4], n1[8], n1[12]);
			hc1 = Avx2.ShiftRightLogical(hc1, 2);
			hc1 = Avx2.And(hc1, And256);
			hc1 = Avx2.Add(hc1, Vector256.CreateScalar(_h1));

			var n2 = MemoryMarshal.Cast<byte, uint>(m.Slice(6));
			var hc2 = IntrinsicsUtils.Create4UInt(n2[0], n2[4], n2[8], n2[12]);
			hc2 = Avx2.ShiftRightLogical(hc2, 4);
			hc2 = Avx2.And(hc2, And256);
			hc2 = Avx2.Add(hc2, Vector256.CreateScalar(_h2));

			var n3 = MemoryMarshal.Cast<byte, uint>(m.Slice(9));
			var hc3 = IntrinsicsUtils.Create4UInt(n3[0], n3[4], n3[8], n3[12]);
			hc3 = Avx2.ShiftRightLogical(hc3, 6);
			hc3 = Avx2.And(hc3, And256);
			hc3 = Avx2.Add(hc3, Vector256.CreateScalar(_h3));

			var n4 = MemoryMarshal.Cast<byte, uint>(m.Slice(12));
			var hc4 = IntrinsicsUtils.Create4UInt(n4[0], n4[4], n4[8], n4[12]);
			hc4 = Avx2.ShiftRightLogical(hc4, 8);
			hc4 = Avx2.Or(hc4, Or256);
			hc4 = Avx2.Add(hc4, Vector256.CreateScalar(_h4));

			var t1 = Avx2.Multiply(_ruwy0, hc0);
			t1 = Avx2.Add(t1, Avx2.Multiply(_svxz4, hc1));
			t1 = Avx2.Add(t1, Avx2.Multiply(_svxz3, hc2));
			t1 = Avx2.Add(t1, Avx2.Multiply(_svxz2, hc3));
			t1 = Avx2.Add(t1, Avx2.Multiply(_svxz1, hc4));
			var d0 = t1.Add4UInt64();

			t1 = Avx2.Multiply(_ruwy1, hc0);
			t1 = Avx2.Add(t1, Avx2.Multiply(_ruwy0, hc1));
			t1 = Avx2.Add(t1, Avx2.Multiply(_svxz4, hc2));
			t1 = Avx2.Add(t1, Avx2.Multiply(_svxz3, hc3));
			t1 = Avx2.Add(t1, Avx2.Multiply(_svxz2, hc4));
			var d1 = t1.Add4UInt64();

			t1 = Avx2.Multiply(_ruwy2, hc0);
			t1 = Avx2.Add(t1, Avx2.Multiply(_ruwy1, hc1));
			t1 = Avx2.Add(t1, Avx2.Multiply(_ruwy0, hc2));
			t1 = Avx2.Add(t1, Avx2.Multiply(_svxz4, hc3));
			t1 = Avx2.Add(t1, Avx2.Multiply(_svxz3, hc4));
			var d2 = t1.Add4UInt64();

			t1 = Avx2.Multiply(_ruwy3, hc0);
			t1 = Avx2.Add(t1, Avx2.Multiply(_ruwy2, hc1));
			t1 = Avx2.Add(t1, Avx2.Multiply(_ruwy1, hc2));
			t1 = Avx2.Add(t1, Avx2.Multiply(_ruwy0, hc3));
			t1 = Avx2.Add(t1, Avx2.Multiply(_svxz4, hc4));
			var d3 = t1.Add4UInt64();

			t1 = Avx2.Multiply(_ruwy4, hc0);
			t1 = Avx2.Add(t1, Avx2.Multiply(_ruwy3, hc1));
			t1 = Avx2.Add(t1, Avx2.Multiply(_ruwy2, hc2));
			t1 = Avx2.Add(t1, Avx2.Multiply(_ruwy1, hc3));
			t1 = Avx2.Add(t1, Avx2.Multiply(_ruwy0, hc4));
			var d4 = t1.Add4UInt64();

			_h0 = (uint)d0 & 0x3ffffff;
			d1 += d0 >> 26;
			_h1 = (uint)d1 & 0x3ffffff;
			d2 += d1 >> 26;
			_h2 = (uint)d2 & 0x3ffffff;
			d3 += d2 >> 26;
			_h3 = (uint)d3 & 0x3ffffff;
			d4 += d3 >> 26;
			_h4 = (uint)d4 & 0x3ffffff;
			_h0 += (uint)((d4 >> 26) * 5);
			_h1 += _h0 >> 26;
			_h0 &= 0x3ffffff;
		}

		public void Update(ReadOnlySpan<byte> source)
		{
			if (Avx2.IsSupported)
			{
				while (source.Length >= BlockSize4)
				{
					Block4(source.Slice(0, BlockSize4));
					source = source.Slice(BlockSize4);
				}
			}

			while (source.Length >= BlockSize2)
			{
				Block2(source.Slice(0, BlockSize2));
				source = source.Slice(BlockSize2);
			}

			if (source.Length >= BlockSize)
			{
				Block(source.Slice(0, BlockSize));
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

		public void Reset()
		{
			_h0 = _h1 = _h2 = _h3 = _h4 = 0;
		}

		public void Dispose() { }
	}
}
