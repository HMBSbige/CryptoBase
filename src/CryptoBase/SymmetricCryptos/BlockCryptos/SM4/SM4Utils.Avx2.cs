using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

internal static partial class SM4Utils
{
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

	extension(ref Vector256<byte> x)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void PreTransform()
		{
			Vector256<byte> vc0f = Vector256.Create((byte)0x0F);
			Vector256<byte> vm1l = Vector256.Create(Vector128.Create(0x9197E2E474720701UL, 0xC7C1B4B222245157UL)).AsByte();
			Vector256<byte> vm1h = Vector256.Create(Vector128.Create(0xE240AB09EB49A200UL, 0xF052B91BF95BB012UL)).AsByte();
			Vector256<byte> t = x & vc0f;
			x &= ~vc0f;
			x = (x.AsUInt32() >>> 4).AsByte();

			t = Avx2.Shuffle(vm1l, t);
			x = Avx2.Shuffle(vm1h, x);
			x ^= t;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void PostTransform()
		{
			Vector256<byte> vc0f = Vector256.Create((byte)0x0F);
			Vector256<byte> vm2l = Vector256.Create(Vector128.Create(0x5B67F2CEA19D0834UL, 0xEDD14478172BBE82UL)).AsByte();
			Vector256<byte> vm2h = Vector256.Create(Vector128.Create(0xAE7201DD73AFDC00UL, 0x11CDBE62CC1063BFUL)).AsByte();
			Vector256<byte> t = ~x & vc0f;
			x = (x.AsUInt32() >>> 4).AsByte();
			x &= vc0f;

			t = Avx2.Shuffle(vm2l, t);
			x = Avx2.Shuffle(vm2h, x);
			x ^= t;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> AesX86EncryptLast(Vector256<byte> x, Vector256<byte> roundKey)
	{
		Vector128<byte> t = AesX86.EncryptLast(x.GetUpper(), roundKey.GetUpper());
		return AesX86.EncryptLast(x.GetLower(), roundKey.GetLower()).ToVector256Unsafe().WithUpper(t);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ref Vector256<byte> r0, ref Vector256<byte> r1, ref Vector256<byte> r2, ref Vector256<byte> r3, Vector256<byte> key, Vector256<byte> c0f, Vector256<byte> vshr)
	{
		Vector256<byte> x = key ^ r1 ^ r2 ^ r3;

		x.PreTransform();
		x = AesX86EncryptLast(x, c0f);
		x.PostTransform();
		x = Avx2.Shuffle(x, vshr);

		Vector256<byte> t = x ^ x.RotateLeftUInt32(8) ^ x.RotateLeftUInt32(16);
		t = t.RotateLeftUInt32(2);
		x = x ^ t ^ x.RotateLeftUInt32(24);

		x ^= r0;
		r0 = r1;
		r1 = r2;
		r2 = r3;
		r3 = x;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer128 ProcessBlockAvx2(scoped in ReadOnlySpan<uint> rk, in VectorBuffer128 source)
	{
		Vector256<byte> c0f = Vector256.Create((byte)0x0F);
		Vector256<byte> vshr = Vector256.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3, 16, 29, 26, 23, 20, 17, 30, 27, 24, 21, 18, 31, 28, 25, 22, 19);

		Unsafe.SkipInit(out VectorBuffer128 r);

		r.V256_0 = source.V256_0.ReverseEndianness32();
		r.V256_1 = source.V256_1.ReverseEndianness32();
		r.V256_2 = source.V256_2.ReverseEndianness32();
		r.V256_3 = source.V256_3.ReverseEndianness32();

		Transpose(ref r.V256_0, ref r.V256_1, ref r.V256_2, ref r.V256_3);

		foreach (uint key in rk)
		{
			Round(ref r.V256_0, ref r.V256_1, ref r.V256_2, ref r.V256_3, Vector256.Create(key).AsByte(), c0f, vshr);
		}

		Transpose(ref r.V256_0, ref r.V256_1, ref r.V256_2, ref r.V256_3);

		r.V256_0 = r.V256_0.ReverseEndianness128();
		r.V256_1 = r.V256_1.ReverseEndianness128();
		r.V256_2 = r.V256_2.ReverseEndianness128();
		r.V256_3 = r.V256_3.ReverseEndianness128();

		return r;
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer256 ProcessBlock(scoped in ReadOnlySpan<uint> rk, in VectorBuffer256 source)
	{
		Vector256<byte> c0f = Vector256.Create((byte)0x0F);
		Vector256<byte> vshr = Vector256.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3, 16, 29, 26, 23, 20, 17, 30, 27, 24, 21, 18, 31, 28, 25, 22, 19);

		Unsafe.SkipInit(out VectorBuffer256 r);

		r.V256_0 = source.V256_0.ReverseEndianness32();
		r.V256_1 = source.V256_1.ReverseEndianness32();
		r.V256_2 = source.V256_2.ReverseEndianness32();
		r.V256_3 = source.V256_3.ReverseEndianness32();
		r.V256_4 = source.V256_4.ReverseEndianness32();
		r.V256_5 = source.V256_5.ReverseEndianness32();
		r.V256_6 = source.V256_6.ReverseEndianness32();
		r.V256_7 = source.V256_7.ReverseEndianness32();

		Transpose(ref r.V256_0, ref r.V256_1, ref r.V256_2, ref r.V256_3);
		Transpose(ref r.V256_4, ref r.V256_5, ref r.V256_6, ref r.V256_7);

		foreach (uint key in rk)
		{
			Vector256<byte> vKey = Vector256.Create(key).AsByte();

			Round(ref r.V256_0, ref r.V256_1, ref r.V256_2, ref r.V256_3, vKey, c0f, vshr);
			Round(ref r.V256_4, ref r.V256_5, ref r.V256_6, ref r.V256_7, vKey, c0f, vshr);
		}

		Transpose(ref r.V256_0, ref r.V256_1, ref r.V256_2, ref r.V256_3);
		Transpose(ref r.V256_4, ref r.V256_5, ref r.V256_6, ref r.V256_7);

		r.V256_0 = r.V256_0.ReverseEndianness128();
		r.V256_1 = r.V256_1.ReverseEndianness128();
		r.V256_2 = r.V256_2.ReverseEndianness128();
		r.V256_3 = r.V256_3.ReverseEndianness128();
		r.V256_4 = r.V256_4.ReverseEndianness128();
		r.V256_5 = r.V256_5.ReverseEndianness128();
		r.V256_6 = r.V256_6.ReverseEndianness128();
		r.V256_7 = r.V256_7.ReverseEndianness128();

		return r;
	}
}
