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

	private static readonly Vector256<byte> vc0f = Vector256.Create((byte)0x0F);
	private static readonly Vector256<byte> vshr = Vector256.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3, 0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);
	private static readonly Vector256<byte> vm1l = Vector256.Create(0x9197E2E474720701, 0xC7C1B4B222245157, 0x9197E2E474720701, 0xC7C1B4B222245157).AsByte();
	private static readonly Vector256<byte> vm1h = Vector256.Create(0xE240AB09EB49A200, 0xF052B91BF95BB012, 0xE240AB09EB49A200, 0xF052B91BF95BB012).AsByte();
	private static readonly Vector256<byte> vm2l = Vector256.Create(0x5B67F2CEA19D0834, 0xEDD14478172BBE82, 0x5B67F2CEA19D0834, 0xEDD14478172BBE82).AsByte();
	private static readonly Vector256<byte> vm2h = Vector256.Create(0xAE7201DD73AFDC00, 0x11CDBE62CC1063BF, 0xAE7201DD73AFDC00, 0x11CDBE62CC1063BF).AsByte();

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
	private static void Transpose(ref Vector256<byte> x0, ref Vector256<byte> x1, ref Vector256<byte> x2, ref Vector256<byte> x3)
	{
		Vector256<ulong> t0 = Avx2.UnpackHigh(x0.AsUInt32(), x1.AsUInt32()).AsUInt64();
		x0 = Avx2.UnpackLow(x0.AsUInt32(), x1.AsUInt32()).AsByte();

		Vector256<ulong> t1 = Avx2.UnpackLow(x2.AsUInt32(), x3.AsUInt32()).AsUInt64();
		x2 = Avx2.UnpackHigh(x2.AsUInt32(), x3.AsUInt32()).AsByte();

		x1 = Avx2.UnpackHigh(x0.AsUInt64(), t1).AsByte();
		x0 = Avx2.UnpackLow(x0.AsUInt64(), t1).AsByte();

		x3 = Avx2.UnpackHigh(t0, x2.AsUInt64()).AsByte();
		x2 = Avx2.UnpackLow(t0, x2.AsUInt64()).AsByte();
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
	private static void PreTransform(this ref Vector256<byte> x)
	{
		Vector256<byte> t = Avx2.And(x, vc0f);
		x = Avx2.AndNot(vc0f, x);
		x = Avx2.ShiftRightLogical(x.AsUInt32(), 4).AsByte();

		t = Avx2.Shuffle(vm1l, t);
		x = Avx2.Shuffle(vm1h, x).Xor(t);
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PostTransform(this ref Vector256<byte> x)
	{
		Vector256<byte> t = Avx2.AndNot(x, vc0f);
		x = Avx2.ShiftRightLogical(x.AsUInt32(), 4).AsByte();
		x = Avx2.And(x, vc0f);

		t = Avx2.Shuffle(vm2l, t);
		x = Avx2.Shuffle(vm2h, x).Xor(t);
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
			Vector128<byte> x = t1
				.Xor(t2)
				.Xor(t3)
				.Xor(Vector128.Create(rk[i]).AsByte());

			x.PreTransform();
			x = Aes.EncryptLast(x, c0f); // AES-NI
			x.PostTransform();

			// inverse MixColumns
			x = Ssse3.Shuffle(x, shr);

			// 4 parallel L1 linear transforms
			Vector128<byte> t = x
				.Xor(x.RotateLeftUInt32_8())
				.Xor(x.RotateLeftUInt32_16())
				.RotateLeftUInt32(2);
			x = x.Xor(t)
				.Xor(x.RotateLeftUInt32_24())
				.Xor(t0);

			// rotate registers
			t0 = t1;
			t1 = t2;
			t2 = t3;
			t3 = x;
		}

		Transpose(ref t0, ref t1, ref t2, ref t3);

		fixed (byte* p = destination)
		{
			Sse2.Store(p + 0 * 16, t0.ReverseEndianness128());
			Sse2.Store(p + 1 * 16, t1.ReverseEndianness128());
			Sse2.Store(p + 2 * 16, t2.ReverseEndianness128());
			Sse2.Store(p + 3 * 16, t3.ReverseEndianness128());
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Encrypt8(uint[] rk, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector128<byte> a0;
		Vector128<byte> a1;
		Vector128<byte> a2;
		Vector128<byte> a3;

		Vector128<byte> b0;
		Vector128<byte> b1;
		Vector128<byte> b2;
		Vector128<byte> b3;

		fixed (byte* p = source)
		{
			a0 = Sse2.LoadVector128(p + 0 * 16).ReverseEndianness32();
			a1 = Sse2.LoadVector128(p + 1 * 16).ReverseEndianness32();
			a2 = Sse2.LoadVector128(p + 2 * 16).ReverseEndianness32();
			a3 = Sse2.LoadVector128(p + 3 * 16).ReverseEndianness32();
			b0 = Sse2.LoadVector128(p + 4 * 16).ReverseEndianness32();
			b1 = Sse2.LoadVector128(p + 5 * 16).ReverseEndianness32();
			b2 = Sse2.LoadVector128(p + 6 * 16).ReverseEndianness32();
			b3 = Sse2.LoadVector128(p + 7 * 16).ReverseEndianness32();
		}

		Transpose(ref a0, ref a1, ref a2, ref a3);
		Transpose(ref b0, ref b1, ref b2, ref b3);

		for (int i = 0; i < 32; ++i)
		{
			Vector128<byte> x0 = Vector128.Create(rk[i]).AsByte();
			Vector128<byte> x1 = x0;

			x0 = x0.Xor(a1).Xor(a2).Xor(a3);
			x0.PreTransform();
			x0 = Aes.EncryptLast(x0, c0f);
			x0.PostTransform();
			x0 = Ssse3.Shuffle(x0, shr);
			Vector128<byte> t0 = x0
				.Xor(x0.RotateLeftUInt32_8())
				.Xor(x0.RotateLeftUInt32_16())
				.RotateLeftUInt32(2);
			x0 = x0.Xor(t0)
				.Xor(x0.RotateLeftUInt32_24())
				.Xor(a0);
			a0 = a1;
			a1 = a2;
			a2 = a3;
			a3 = x0;

			x1 = x1.Xor(b1).Xor(b2).Xor(b3);
			x1.PreTransform();
			x1 = Aes.EncryptLast(x1, c0f);
			x1.PostTransform();
			x1 = Ssse3.Shuffle(x1, shr);
			Vector128<byte> t1 = x1
				.Xor(x1.RotateLeftUInt32_8())
				.Xor(x1.RotateLeftUInt32_16())
				.RotateLeftUInt32(2);
			x1 = x1.Xor(t1)
				.Xor(x1.RotateLeftUInt32_24())
				.Xor(b0);
			b0 = b1;
			b1 = b2;
			b2 = b3;
			b3 = x1;
		}

		Transpose(ref a0, ref a1, ref a2, ref a3);
		Transpose(ref b0, ref b1, ref b2, ref b3);

		fixed (byte* p = destination)
		{
			Sse2.Store(p + 0 * 16, a0.ReverseEndianness128());
			Sse2.Store(p + 1 * 16, a1.ReverseEndianness128());
			Sse2.Store(p + 2 * 16, a2.ReverseEndianness128());
			Sse2.Store(p + 3 * 16, a3.ReverseEndianness128());
			Sse2.Store(p + 4 * 16, b0.ReverseEndianness128());
			Sse2.Store(p + 5 * 16, b1.ReverseEndianness128());
			Sse2.Store(p + 6 * 16, b2.ReverseEndianness128());
			Sse2.Store(p + 7 * 16, b3.ReverseEndianness128());
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static unsafe void Encrypt16(uint[] rk, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector256<byte> a0;
		Vector256<byte> a1;
		Vector256<byte> a2;
		Vector256<byte> a3;

		Vector256<byte> b0;
		Vector256<byte> b1;
		Vector256<byte> b2;
		Vector256<byte> b3;

		fixed (byte* p = source)
		{
			a0 = Avx.LoadVector256(p + 0 * 32).ReverseEndianness32();
			a1 = Avx.LoadVector256(p + 1 * 32).ReverseEndianness32();
			a2 = Avx.LoadVector256(p + 2 * 32).ReverseEndianness32();
			a3 = Avx.LoadVector256(p + 3 * 32).ReverseEndianness32();
			b0 = Avx.LoadVector256(p + 4 * 32).ReverseEndianness32();
			b1 = Avx.LoadVector256(p + 5 * 32).ReverseEndianness32();
			b2 = Avx.LoadVector256(p + 6 * 32).ReverseEndianness32();
			b3 = Avx.LoadVector256(p + 7 * 32).ReverseEndianness32();
		}

		Transpose(ref a0, ref a1, ref a2, ref a3);
		Transpose(ref b0, ref b1, ref b2, ref b3);

		for (int i = 0; i < 32; ++i)
		{
			Vector256<byte> x0 = Vector256.Create(rk[i]).AsByte();
			Vector256<byte> x1 = x0;

			x0 = x0.Xor(a1).Xor(a2).Xor(a3);
			x0.PreTransform();
			Vector128<byte> u0 = Aes.EncryptLast(x0.GetUpper(), c0f);
			x0 = Aes.EncryptLast(x0.GetLower(), c0f).ToVector256Unsafe().WithUpper(u0);
			x0.PostTransform();
			x0 = Avx2.Shuffle(x0, vshr);
			Vector256<byte> t0 = x0
				.Xor(x0.RotateLeftUInt32_8())
				.Xor(x0.RotateLeftUInt32_16())
				.RotateLeftUInt32(2);
			x0 = x0.Xor(t0)
				.Xor(x0.RotateLeftUInt32_24())
				.Xor(a0);
			a0 = a1;
			a1 = a2;
			a2 = a3;
			a3 = x0;

			x1 = x1.Xor(b1).Xor(b2).Xor(b3);
			x1.PreTransform();
			Vector128<byte> u1 = Aes.EncryptLast(x1.GetUpper(), c0f);
			x1 = Aes.EncryptLast(x1.GetLower(), c0f).ToVector256Unsafe().WithUpper(u1);
			x1.PostTransform();
			x1 = Avx2.Shuffle(x1, vshr);
			Vector256<byte> t1 = x1
				.Xor(x1.RotateLeftUInt32_8())
				.Xor(x1.RotateLeftUInt32_16())
				.RotateLeftUInt32(2);
			x1 = x1.Xor(t1)
				.Xor(x1.RotateLeftUInt32_24())
				.Xor(b0);
			b0 = b1;
			b1 = b2;
			b2 = b3;
			b3 = x1;
		}

		Transpose(ref a0, ref a1, ref a2, ref a3);
		Transpose(ref b0, ref b1, ref b2, ref b3);

		fixed (byte* p = destination)
		{
			Avx.Store(p + 0 * 32, a0.ReverseEndianness128());
			Avx.Store(p + 1 * 32, a1.ReverseEndianness128());
			Avx.Store(p + 2 * 32, a2.ReverseEndianness128());
			Avx.Store(p + 3 * 32, a3.ReverseEndianness128());
			Avx.Store(p + 4 * 32, b0.ReverseEndianness128());
			Avx.Store(p + 5 * 32, b1.ReverseEndianness128());
			Avx.Store(p + 6 * 32, b2.ReverseEndianness128());
			Avx.Store(p + 7 * 32, b3.ReverseEndianness128());
		}
	}
}
