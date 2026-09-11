using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

internal static partial class SM4Utils
{
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

	extension(ref Vector128<byte> x)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void PreTransform()
		{
			Vector128<byte> c0f = Vector128.Create((byte)0x0F);
			Vector128<byte> m1l = Vector128.Create(0x9197E2E474720701, 0xC7C1B4B222245157).AsByte();
			Vector128<byte> m1h = Vector128.Create(0xE240AB09EB49A200, 0xF052B91BF95BB012).AsByte();
			Vector128<byte> t = x & c0f;
			x &= ~c0f;
			x = (x.AsUInt32() >>> 4).AsByte();
			t = Vector128.ShuffleNative(m1l, t);
			x = Vector128.ShuffleNative(m1h, x);
			x ^= t;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void PostTransform()
		{
			Vector128<byte> c0f = Vector128.Create((byte)0x0F);
			Vector128<byte> m2l = Vector128.Create(0x5B67F2CEA19D0834, 0xEDD14478172BBE82).AsByte();
			Vector128<byte> m2h = Vector128.Create(0xAE7201DD73AFDC00, 0x11CDBE62CC1063BF).AsByte();
			Vector128<byte> t = ~x & c0f;
			x = (x.AsUInt32() >>> 4).AsByte();
			x &= c0f;

			t = Vector128.ShuffleNative(m2l, t);
			x = Vector128.ShuffleNative(m2h, x);
			x ^= t;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ref Vector128<byte> r0, ref Vector128<byte> r1, ref Vector128<byte> r2, ref Vector128<byte> r3, Vector128<byte> key, Vector128<byte> c0f, Vector128<byte> shr)
	{
		Vector128<byte> x = key ^ r1 ^ r2 ^ r3;

		x.PreTransform();
		x = AesX86.EncryptLast(x, c0f);// AES-NI
		x.PostTransform();

		// inverse MixColumns
		x = Vector128.ShuffleNative(x, shr);

		// 4 parallel L1 linear transforms
		Vector128<byte> t = x ^ x.RotateLeftUInt32(8) ^ x.RotateLeftUInt32(16);
		t = t.RotateLeftUInt32(2);
		x = x ^ t ^ x.RotateLeftUInt32(24);

		// rotate registers
		x ^= r0;
		r0 = r1;
		r1 = r2;
		r2 = r3;
		r3 = x;
	}

	/// <summary>
	/// https://github.com/mjosaarinen/sm4ni/blob/master/sm4ni.c
	/// </summary>
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer64 ProcessBlock(scoped in ReadOnlySpan<uint> rk, in VectorBuffer64 source)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> shr = Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);

		Unsafe.SkipInit(out VectorBuffer64 r);

		r.V128_0 = source.V128_0.ReverseEndianness32();
		r.V128_1 = source.V128_1.ReverseEndianness32();
		r.V128_2 = source.V128_2.ReverseEndianness32();
		r.V128_3 = source.V128_3.ReverseEndianness32();

		Transpose(ref r.V128_0, ref r.V128_1, ref r.V128_2, ref r.V128_3);

		foreach (uint key in rk)
		{
			Round(ref r.V128_0, ref r.V128_1, ref r.V128_2, ref r.V128_3, Vector128.Create(key).AsByte(), c0f, shr);
		}

		Transpose(ref r.V128_0, ref r.V128_1, ref r.V128_2, ref r.V128_3);

		r.V128_0 = r.V128_0.ReverseEndianness128();
		r.V128_1 = r.V128_1.ReverseEndianness128();
		r.V128_2 = r.V128_2.ReverseEndianness128();
		r.V128_3 = r.V128_3.ReverseEndianness128();

		return r;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer128 ProcessBlock(scoped in ReadOnlySpan<uint> rk, in VectorBuffer128 source)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> shr = Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);

		Unsafe.SkipInit(out VectorBuffer128 r);

		r.V128_0 = source.V128_0.ReverseEndianness32();
		r.V128_1 = source.V128_1.ReverseEndianness32();
		r.V128_2 = source.V128_2.ReverseEndianness32();
		r.V128_3 = source.V128_3.ReverseEndianness32();
		r.V128_4 = source.V128_4.ReverseEndianness32();
		r.V128_5 = source.V128_5.ReverseEndianness32();
		r.V128_6 = source.V128_6.ReverseEndianness32();
		r.V128_7 = source.V128_7.ReverseEndianness32();

		Transpose(ref r.V128_0, ref r.V128_1, ref r.V128_2, ref r.V128_3);
		Transpose(ref r.V128_4, ref r.V128_5, ref r.V128_6, ref r.V128_7);

		foreach (uint key in rk)
		{
			Vector128<byte> vKey = Vector128.Create(key).AsByte();

			Round(ref r.V128_0, ref r.V128_1, ref r.V128_2, ref r.V128_3, vKey, c0f, shr);
			Round(ref r.V128_4, ref r.V128_5, ref r.V128_6, ref r.V128_7, vKey, c0f, shr);
		}

		Transpose(ref r.V128_0, ref r.V128_1, ref r.V128_2, ref r.V128_3);
		Transpose(ref r.V128_4, ref r.V128_5, ref r.V128_6, ref r.V128_7);

		r.V128_0 = r.V128_0.ReverseEndianness128();
		r.V128_1 = r.V128_1.ReverseEndianness128();
		r.V128_2 = r.V128_2.ReverseEndianness128();
		r.V128_3 = r.V128_3.ReverseEndianness128();
		r.V128_4 = r.V128_4.ReverseEndianness128();
		r.V128_5 = r.V128_5.ReverseEndianness128();
		r.V128_6 = r.V128_6.ReverseEndianness128();
		r.V128_7 = r.V128_7.ReverseEndianness128();

		return r;
	}
}
