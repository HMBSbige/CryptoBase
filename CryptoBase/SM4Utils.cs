using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase
{
	public static class SM4Utils
	{
		private static readonly Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		private static readonly Vector128<byte> shr = Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);
		private static readonly Vector128<byte> m1l = Vector128.Create(0x9197E2E474720701, 0xC7C1B4B222245157).AsByte();
		private static readonly Vector128<byte> m1h = Vector128.Create(0xE240AB09EB49A200, 0xF052B91BF95BB012).AsByte();
		private static readonly Vector128<byte> m2l = Vector128.Create(0x5B67F2CEA19D0834, 0xEDD14478172BBE82).AsByte();
		private static readonly Vector128<byte> m2h = Vector128.Create(0xAE7201DD73AFDC00, 0x11CDBE62CC1063BF).AsByte();

		/// <summary>
		/// https://github.com/mjosaarinen/sm4ni/blob/master/sm4ni.c
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static unsafe void Encrypt4(uint[] rk, ReadOnlySpan<byte> source, Span<byte> destination)
		{
			var p32 = MemoryMarshal.Cast<byte, uint>(source);
			var t3 = Vector128.Create(p32[3], p32[7], p32[11], p32[15]).ReverseEndianness32();
			var t2 = Vector128.Create(p32[2], p32[6], p32[10], p32[14]).ReverseEndianness32();
			var t1 = Vector128.Create(p32[1], p32[5], p32[9], p32[13]).ReverseEndianness32();
			var t0 = Vector128.Create(p32[0], p32[4], p32[8], p32[12]).ReverseEndianness32();

			for (var i = 0; i < 32; ++i)
			{
				var x = t1.Xor(t2).Xor(t3).Xor(Vector128.Create(rk[i]).AsByte());

				var y = Sse2.And(x, c0f); // inner affine
				y = Ssse3.Shuffle(m1l, y);
				x = Sse2.ShiftRightLogical(x.AsUInt64(), 4).AsByte();
				x = Sse2.And(x, c0f);
				x = Ssse3.Shuffle(m1h, x).Xor(y);

				x = Ssse3.Shuffle(x, shr); // inverse MixColumns
				x = Aes.EncryptLast(x, c0f); // AES-NI

				y = Sse2.AndNot(x, c0f); // outer affine
				y = Ssse3.Shuffle(m2l, y);
				x = Sse2.ShiftRightLogical(x.AsUInt64(), 4).AsByte();
				x = Sse2.And(x, c0f);
				x = Ssse3.Shuffle(m2h, x).Xor(y);

				// 4 parallel L1 linear transforms
				y = x.Xor(x.RotateLeftUInt32_8()).Xor(x.RotateLeftUInt32_16());
				y = y.AsUInt32().RotateLeftUInt32(2).AsByte();
				x = x.Xor(y).Xor(x.RotateLeftUInt32_24());

				// rotate registers
				x = x.Xor(t0);
				t0 = t1;
				t1 = t2;
				t2 = t3;
				t3 = x;
			}

			var a = t3.ReverseEndianness32().AsUInt32();
			var b = t2.ReverseEndianness32().AsUInt32();
			var c = t1.ReverseEndianness32().AsUInt32();
			var d = t0.ReverseEndianness32().AsUInt32();

			var x0 = Sse2.UnpackLow(a, b);
			var x1 = Sse2.UnpackLow(c, d);
			var x2 = Sse2.UnpackHigh(a, b);
			var x3 = Sse2.UnpackHigh(c, d);

			t0 = Sse2.UnpackLow(x0.AsUInt64(), x1.AsUInt64()).AsByte();
			t1 = Sse2.UnpackHigh(x0.AsUInt64(), x1.AsUInt64()).AsByte();
			t2 = Sse2.UnpackLow(x2.AsUInt64(), x3.AsUInt64()).AsByte();
			t3 = Sse2.UnpackHigh(x2.AsUInt64(), x3.AsUInt64()).AsByte();

			fixed (byte* p = destination)
			{
				Sse2.Store(p, t0);
				Sse2.Store(p + 16, t1);
				Sse2.Store(p + 32, t2);
				Sse2.Store(p + 48, t3);
			}
		}
	}
}
