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
		public const int TagSize = 16;

		private readonly uint _x0, _x1, _x2, _x3;
		protected uint H0, H1, H2, H3, H4;

		private readonly Vector128<uint> _r0s4, _s3s2, _r1r0, _s4s3, _s1s2, _r2r1, _r3r2, _s3s4, _r4r3, _r0;

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
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		private void Block(ReadOnlySpan<byte> m)
		{
			var h01 = IntrinsicsUtils.CreateTwoUInt(H0, H1);
			var h23 = IntrinsicsUtils.CreateTwoUInt(H2, H3);
			var h44 = IntrinsicsUtils.CreateTwoUInt(H4, H4);

			var m06 = IntrinsicsUtils.CreateTwoUInt(BinaryPrimitives.ReadUInt32LittleEndian(m) & 0x3ffffff, BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(3)) >> 2 & 0x3ffffff);
			h01 = Sse2.Add(h01, m06);
			var m612 = IntrinsicsUtils.CreateTwoUInt(BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(6)) >> 4 & 0x3ffffff, BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(9)) >> 6 & 0x3ffffff);
			h23 = Sse2.Add(h23, m612);
			var m4 = BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(12)) >> 8 | 1u << 24;
			h44 = Sse2.Add(h44, IntrinsicsUtils.CreateTwoUInt(m4));

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
			var d0 = t.ToScalar();
			var d1 = Sse2.ShiftRightLogical128BitLane(t, 8).ToScalar();

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
			var d2 = t.ToScalar();
			var d3 = Sse2.ShiftRightLogical128BitLane(t, 8).ToScalar();

			// h0 * r4 + h2 * r2
			// h1 * r3 + h3 * r1
			t00 = Sse2.Multiply(h01, _r4r3);
			t01 = Sse2.Multiply(h23, _r2r1);
			t1 = Sse2.Add(t01, t00);
			// h4 * r0
			t3 = Sse2.Multiply(h44, _r0);
			// d4 = t1[0] + t1[1] + t3[0]
			var d4 = t1.Add(Sse2.ShiftRightLogical128BitLane(t1, 8)).Add(t3).ToScalar();

			H0 = (uint)d0 & 0x3ffffff;
			d1 += (uint)(d0 >> 26);
			H1 = (uint)d1 & 0x3ffffff;
			d2 += (uint)(d1 >> 26);
			H2 = (uint)d2 & 0x3ffffff;
			d3 += (uint)(d2 >> 26);
			H3 = (uint)d3 & 0x3ffffff;
			d4 += (uint)(d3 >> 26);
			H4 = (uint)d4 & 0x3ffffff;
			H0 += (uint)(d4 >> 26) * 5;
			H1 += H0 >> 26;
			H0 &= 0x3ffffff;
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
			H2 += H1 >> 26;
			H1 &= 0x3ffffff;
			H3 += H2 >> 26;
			H2 &= 0x3ffffff;
			H4 += H3 >> 26;
			H3 &= 0x3ffffff;
			H0 += (H4 >> 26) * 5;
			H4 &= 0x3ffffff;
			H1 += H0 >> 26;
			H0 &= 0x3ffffff;

			var g0 = H0 + 5;
			var g1 = H1 + (g0 >> 26);
			g0 &= 0x3ffffff;
			var g2 = H2 + (g1 >> 26);
			g1 &= 0x3ffffff;
			var g3 = H3 + (g2 >> 26);
			g2 &= 0x3ffffff;
			var g4 = H4 + (g3 >> 26) - (1u << 26);
			g3 &= 0x3ffffff;

			var mask = (g4 >> 31) - 1;
			g0 &= mask;
			g1 &= mask;
			g2 &= mask;
			g3 &= mask;
			g4 &= mask;
			mask = ~mask;
			H0 = H0 & mask | g0;
			H1 = H1 & mask | g1;
			H2 = H2 & mask | g2;
			H3 = H3 & mask | g3;
			H4 = H4 & mask | g4;

			var f0 = (H0 | H1 << 26) + (ulong)_x0;
			var f1 = (H1 >> 6 | H2 << 20) + (ulong)_x1;
			var f2 = (H2 >> 12 | H3 << 14) + (ulong)_x2;
			var f3 = (H3 >> 18 | H4 << 8) + (ulong)_x3;

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
			H0 = H1 = H2 = H3 = H4 = 0;
		}

		public void Dispose() { }
	}
}
