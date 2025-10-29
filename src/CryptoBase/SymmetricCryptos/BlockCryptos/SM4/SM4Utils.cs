namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

public static class SM4Utils
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
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> m1l = Vector128.Create(0x9197E2E474720701, 0xC7C1B4B222245157).AsByte();
		Vector128<byte> m1h = Vector128.Create(0xE240AB09EB49A200, 0xF052B91BF95BB012).AsByte();
		Vector128<byte> t = x & c0f;
		x &= ~c0f;
		x = (x.AsUInt32() >>> 4).AsByte();
		t = Ssse3.Shuffle(m1l, t);
		x = Ssse3.Shuffle(m1h, x);
		x ^= t;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PreTransform(this ref Vector256<byte> x)
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
	private static void PostTransform(this ref Vector128<byte> x)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> m2l = Vector128.Create(0x5B67F2CEA19D0834, 0xEDD14478172BBE82).AsByte();
		Vector128<byte> m2h = Vector128.Create(0xAE7201DD73AFDC00, 0x11CDBE62CC1063BF).AsByte();
		Vector128<byte> t = ~x & c0f;
		x = (x.AsUInt32() >>> 4).AsByte();
		x &= c0f;

		t = Ssse3.Shuffle(m2l, t);
		x = Ssse3.Shuffle(m2h, x);
		x ^= t;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PostTransform(this ref Vector256<byte> x)
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

	/// <summary>
	/// https://github.com/mjosaarinen/sm4ni/blob/master/sm4ni.c
	/// </summary>
	public static void Encrypt4(uint[] rk, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> shr = Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);
		Vector128<byte> t0 = Vector128.Create(source).ReverseEndianness32();
		Vector128<byte> t1 = Vector128.Create(source.Slice(16)).ReverseEndianness32();
		Vector128<byte> t2 = Vector128.Create(source.Slice(32)).ReverseEndianness32();
		Vector128<byte> t3 = Vector128.Create(source.Slice(48)).ReverseEndianness32();

		Transpose(ref t0, ref t1, ref t2, ref t3);

		for (int i = 0; i < 32; ++i)
		{
			Vector128<byte> x = t1 ^ t2 ^ t3 ^ Vector128.Create(rk[i]).AsByte();

			x.PreTransform();
			x = AesX86.EncryptLast(x, c0f);// AES-NI
			x.PostTransform();

			// inverse MixColumns
			x = Ssse3.Shuffle(x, shr);

			// 4 parallel L1 linear transforms
			Vector128<byte> t = x ^ x.RotateLeftUInt32_8() ^ x.RotateLeftUInt32_16();
			t = t.RotateLeftUInt32(2);
			x = x ^ t ^ x.RotateLeftUInt32_24();

			// rotate registers
			x ^= t0;
			t0 = t1;
			t1 = t2;
			t2 = t3;
			t3 = x;
		}

		Transpose(ref t0, ref t1, ref t2, ref t3);

		t0.ReverseEndianness128().CopyTo(destination);
		t1.ReverseEndianness128().CopyTo(destination.Slice(16));
		t2.ReverseEndianness128().CopyTo(destination.Slice(32));
		t3.ReverseEndianness128().CopyTo(destination.Slice(48));
	}

	public static void Encrypt8(uint[] rk, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> shr = Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);
		Vector128<byte> a0 = Vector128.Create(source).ReverseEndianness32();
		Vector128<byte> a1 = Vector128.Create(source.Slice(16)).ReverseEndianness32();
		Vector128<byte> a2 = Vector128.Create(source.Slice(32)).ReverseEndianness32();
		Vector128<byte> a3 = Vector128.Create(source.Slice(48)).ReverseEndianness32();

		Vector128<byte> b0 = Vector128.Create(source.Slice(64)).ReverseEndianness32();
		Vector128<byte> b1 = Vector128.Create(source.Slice(80)).ReverseEndianness32();
		Vector128<byte> b2 = Vector128.Create(source.Slice(96)).ReverseEndianness32();
		Vector128<byte> b3 = Vector128.Create(source.Slice(112)).ReverseEndianness32();

		Transpose(ref a0, ref a1, ref a2, ref a3);
		Transpose(ref b0, ref b1, ref b2, ref b3);

		for (int i = 0; i < 32; ++i)
		{
			Vector128<byte> x0 = Vector128.Create(rk[i]).AsByte();
			Vector128<byte> x1 = x0;

			x0 = x0 ^ a1 ^ a2 ^ a3;
			x0.PreTransform();
			x0 = AesX86.EncryptLast(x0, c0f);
			x0.PostTransform();
			x0 = Ssse3.Shuffle(x0, shr);
			Vector128<byte> t0 = x0 ^ x0.RotateLeftUInt32_8() ^ x0.RotateLeftUInt32_16();
			t0 = t0.RotateLeftUInt32(2);
			x0 = x0 ^ t0 ^ x0.RotateLeftUInt32_24() ^ a0;
			a0 = a1;
			a1 = a2;
			a2 = a3;
			a3 = x0;

			x1 = x1 ^ b1 ^ b2 ^ b3;
			x1.PreTransform();
			x1 = AesX86.EncryptLast(x1, c0f);
			x1.PostTransform();
			x1 = Ssse3.Shuffle(x1, shr);
			Vector128<byte> t1 = x1 ^ x1.RotateLeftUInt32_8() ^ x1.RotateLeftUInt32_16();
			t1 = t1.RotateLeftUInt32(2);
			x1 = x1 ^ t1 ^ x1.RotateLeftUInt32_24() ^ b0;
			b0 = b1;
			b1 = b2;
			b2 = b3;
			b3 = x1;
		}

		Transpose(ref a0, ref a1, ref a2, ref a3);
		Transpose(ref b0, ref b1, ref b2, ref b3);

		a0.ReverseEndianness128().CopyTo(destination);
		a1.ReverseEndianness128().CopyTo(destination.Slice(16));
		a2.ReverseEndianness128().CopyTo(destination.Slice(32));
		a3.ReverseEndianness128().CopyTo(destination.Slice(48));
		b0.ReverseEndianness128().CopyTo(destination.Slice(64));
		b1.ReverseEndianness128().CopyTo(destination.Slice(80));
		b2.ReverseEndianness128().CopyTo(destination.Slice(96));
		b3.ReverseEndianness128().CopyTo(destination.Slice(112));
	}

	public static void Encrypt16(uint[] rk, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector256<byte> vshr = Vector256.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3, 16, 29, 26, 23, 20, 17, 30, 27, 24, 21, 18, 31, 28, 25, 22, 19);
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref Vector256<byte> s0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 0 * 32));
		ref Vector256<byte> s1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 1 * 32));
		ref Vector256<byte> s2 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 2 * 32));
		ref Vector256<byte> s3 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 3 * 32));
		ref Vector256<byte> s4 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 4 * 32));
		ref Vector256<byte> s5 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 5 * 32));
		ref Vector256<byte> s6 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 6 * 32));
		ref Vector256<byte> s7 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 7 * 32));

		Vector256<byte> a0 = s0.ReverseEndianness32();
		Vector256<byte> a1 = s1.ReverseEndianness32();
		Vector256<byte> a2 = s2.ReverseEndianness32();
		Vector256<byte> a3 = s3.ReverseEndianness32();
		Vector256<byte> b0 = s4.ReverseEndianness32();
		Vector256<byte> b1 = s5.ReverseEndianness32();
		Vector256<byte> b2 = s6.ReverseEndianness32();
		Vector256<byte> b3 = s7.ReverseEndianness32();

		Transpose(ref a0, ref a1, ref a2, ref a3);
		Transpose(ref b0, ref b1, ref b2, ref b3);

		for (int i = 0; i < 32; ++i)
		{
			Vector256<byte> x0 = Vector256.Create(rk[i]).AsByte();
			Vector256<byte> x1 = x0;

			x0 = x0 ^ a1 ^ a2 ^ a3;
			x0.PreTransform();
			Vector128<byte> u0 = AesX86.EncryptLast(x0.GetUpper(), c0f);
			x0 = AesX86.EncryptLast(x0.GetLower(), c0f).ToVector256Unsafe().WithUpper(u0);
			x0.PostTransform();
			x0 = Avx2.Shuffle(x0, vshr);
			Vector256<byte> t0 = x0 ^ x0.RotateLeftUInt32_8() ^ x0.RotateLeftUInt32_16();
			t0 = t0.RotateLeftUInt32(2);
			x0 = x0 ^ t0 ^ x0.RotateLeftUInt32_24() ^ a0;
			a0 = a1;
			a1 = a2;
			a2 = a3;
			a3 = x0;

			x1 = x1 ^ b1 ^ b2 ^ b3;
			x1.PreTransform();
			Vector128<byte> u1 = AesX86.EncryptLast(x1.GetUpper(), c0f);
			x1 = AesX86.EncryptLast(x1.GetLower(), c0f).ToVector256Unsafe().WithUpper(u1);
			x1.PostTransform();
			x1 = Avx2.Shuffle(x1, vshr);
			Vector256<byte> t1 = x1 ^ x1.RotateLeftUInt32_8() ^ x1.RotateLeftUInt32_16();
			t1 = t1.RotateLeftUInt32(2);
			x1 = x1 ^ t1 ^ x1.RotateLeftUInt32_24() ^ b0;
			b0 = b1;
			b1 = b2;
			b2 = b3;
			b3 = x1;
		}

		Transpose(ref a0, ref a1, ref a2, ref a3);
		Transpose(ref b0, ref b1, ref b2, ref b3);

		a0 = a0.ReverseEndianness128();
		a1 = a1.ReverseEndianness128();
		a2 = a2.ReverseEndianness128();
		a3 = a3.ReverseEndianness128();
		b0 = b0.ReverseEndianness128();
		b1 = b1.ReverseEndianness128();
		b2 = b2.ReverseEndianness128();
		b3 = b3.ReverseEndianness128();

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 0 * 32), a0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 1 * 32), a1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 2 * 32), a2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 3 * 32), a3);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 4 * 32), b0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 5 * 32), b1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 6 * 32), b2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 7 * 32), b3);
	}
}
