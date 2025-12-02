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
			Vector256<byte> vm1l = Vector256.Create(0x9197E2E474720701, 0xC7C1B4B222245157, 0x9197E2E474720701, 0xC7C1B4B222245157).AsByte();
			Vector256<byte> vm1h = Vector256.Create(0xE240AB09EB49A200, 0xF052B91BF95BB012, 0xE240AB09EB49A200, 0xF052B91BF95BB012).AsByte();
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
			Vector256<byte> vm2l = Vector256.Create(0x5B67F2CEA19D0834, 0xEDD14478172BBE82, 0x5B67F2CEA19D0834, 0xEDD14478172BBE82).AsByte();
			Vector256<byte> vm2h = Vector256.Create(0xAE7201DD73AFDC00, 0x11CDBE62CC1063BF, 0xAE7201DD73AFDC00, 0x11CDBE62CC1063BF).AsByte();
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

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer256 ProcessBlock(scoped in ReadOnlySpan<uint> rk, scoped in VectorBuffer256 source)
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
			Vector256<byte> x0 = Vector256.Create(key).AsByte();
			Vector256<byte> x1 = x0;

			x0 = x0 ^ r.V256_1 ^ r.V256_2 ^ r.V256_3;
			x0.PreTransform();
			x0 = AesX86EncryptLast(x0, c0f);
			x0.PostTransform();
			x0 = Avx2.Shuffle(x0, vshr);
			Vector256<byte> t0 = x0 ^ x0.RotateLeftUInt32_8() ^ x0.RotateLeftUInt32_16();
			t0 = t0.RotateLeftUInt32(2);
			x0 = x0 ^ t0 ^ x0.RotateLeftUInt32_24() ^ r.V256_0;
			r.V256_0 = r.V256_1;
			r.V256_1 = r.V256_2;
			r.V256_2 = r.V256_3;
			r.V256_3 = x0;

			x1 = x1 ^ r.V256_5 ^ r.V256_6 ^ r.V256_7;
			x1.PreTransform();
			x1 = AesX86EncryptLast(x1, c0f);
			x1.PostTransform();
			x1 = Avx2.Shuffle(x1, vshr);
			Vector256<byte> t1 = x1 ^ x1.RotateLeftUInt32_8() ^ x1.RotateLeftUInt32_16();
			t1 = t1.RotateLeftUInt32(2);
			x1 = x1 ^ t1 ^ x1.RotateLeftUInt32_24() ^ r.V256_4;
			r.V256_4 = r.V256_5;
			r.V256_5 = r.V256_6;
			r.V256_6 = r.V256_7;
			r.V256_7 = x1;
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
