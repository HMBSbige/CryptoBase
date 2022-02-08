using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

public static class SM4Utils
{
	private static readonly Vector128<byte> c0f = Vector128.Create((byte)0x0F);
	private static readonly Vector128<byte> shr = Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);
	private static readonly Vector128<byte> m1l = Vector128.Create(0x9197E2E474720701, 0xC7C1B4B222245157).AsByte();
	private static readonly Vector128<byte> m1h = Vector128.Create(0xE240AB09EB49A200, 0xF052B91BF95BB012).AsByte();
	private static readonly Vector128<byte> m2l = Vector128.Create(0x5B67F2CEA19D0834, 0xEDD14478172BBE82).AsByte();
	private static readonly Vector128<byte> m2h = Vector128.Create(0xAE7201DD73AFDC00, 0x11CDBE62CC1063BF).AsByte();

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Transpose(ref Vector128<byte> x0, ref Vector128<byte> x1, ref Vector128<byte> x2, ref Vector128<byte> x3)
	{
		Vector128<ulong> t0 = Sse2.UnpackHigh(x0.AsUInt32(), x1.AsUInt32()).AsUInt64();
		x0 = Sse2.UnpackLow(x0.AsUInt32(), x1.AsUInt32()).AsByte();

		Vector128<ulong> t1 = Sse2.UnpackLow(x2.AsUInt32(), x3.AsUInt32()).AsUInt64();
		x2 = Sse2.UnpackHigh(x2.AsUInt32(), x3.AsUInt32()).AsByte();

		x1 = Sse2.UnpackHigh(x0.AsUInt64(), t1).AsByte();
		x0 = Sse2.UnpackLow(x0.AsUInt64(), t1).AsByte();

		x3 = Sse2.UnpackHigh(t0, x2.AsUInt64()).AsByte();
		x2 = Sse2.UnpackLow(t0, x2.AsUInt64()).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PreTransform(this ref Vector128<byte> x)
	{
		Vector128<byte> t = Sse2.And(x, c0f);
		x = Sse2.AndNot(c0f, x);
		x = Sse2.ShiftRightLogical(x.AsUInt32(), 4).AsByte();

		t = Ssse3.Shuffle(m1l, t);
		x = Ssse3.Shuffle(m1h, x).Xor(t);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PostTransform(this ref Vector128<byte> x)
	{
		Vector128<byte> t = Sse2.AndNot(x, c0f);
		x = Sse2.ShiftRightLogical(x.AsUInt32(), 4).AsByte();
		x = Sse2.And(x, c0f);

		t = Ssse3.Shuffle(m2l, t);
		x = Ssse3.Shuffle(m2h, x).Xor(t);
	}

	/// <summary>
	/// https://github.com/mjosaarinen/sm4ni/blob/master/sm4ni.c
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Encrypt4(uint[] rk, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector128<byte> t0;
		Vector128<byte> t1;
		Vector128<byte> t2;
		Vector128<byte> t3;

		fixed (byte* p = source)
		{
			t0 = Sse2.LoadVector128(p + 0 * 16).ReverseEndianness32();
			t1 = Sse2.LoadVector128(p + 1 * 16).ReverseEndianness32();
			t2 = Sse2.LoadVector128(p + 2 * 16).ReverseEndianness32();
			t3 = Sse2.LoadVector128(p + 3 * 16).ReverseEndianness32();
		}

		Transpose(ref t0, ref t1, ref t2, ref t3);

		for (int i = 0; i < 32; ++i)
		{
			Vector128<byte> x = t1.Xor(t2).Xor(t3).Xor(Vector128.Create(rk[i]).AsByte());

			x.PreTransform();
			x = Aes.EncryptLast(x, c0f); // AES-NI
			x.PostTransform();

			// inverse MixColumns
			x = Ssse3.Shuffle(x, shr);

			// 4 parallel L1 linear transforms
			Vector128<byte> t = x.Xor(x.RotateLeftUInt32_8()).Xor(x.RotateLeftUInt32_16());
			t = t.AsUInt32().RotateLeftUInt32(2).AsByte();
			x = x.Xor(t).Xor(x.RotateLeftUInt32_24());
			x = x.Xor(t0);

			// rotate registers
			t0 = t1;
			t1 = t2;
			t2 = t3;
			t3 = x;
		}

		Transpose(ref t0, ref t1, ref t2, ref t3);

		fixed (byte* p = destination)
		{
			Sse2.Store(p + 0 * 16, t0.Reverse());
			Sse2.Store(p + 1 * 16, t1.Reverse());
			Sse2.Store(p + 2 * 16, t2.Reverse());
			Sse2.Store(p + 3 * 16, t3.Reverse());
		}
	}
}
