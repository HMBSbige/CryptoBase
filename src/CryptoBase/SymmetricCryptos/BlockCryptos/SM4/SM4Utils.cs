namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4;

public static class SM4Utils
{
	private static ReadOnlySpan<byte> S =>
	[
		0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
		0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
		0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
		0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
		0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
		0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
		0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
		0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
		0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
		0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
		0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
		0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
		0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
		0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
		0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
		0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
	];

	private static ReadOnlySpan<uint> Ck =>
	[
		0x00070e15,
		0x1c232a31,
		0x383f464d,
		0x545b6269,
		0x70777e85,
		0x8c939aa1,
		0xa8afb6bd,
		0xc4cbd2d9,
		0xe0e7eef5,
		0xfc030a11,
		0x181f262d,
		0x343b4249,
		0x50575e65,
		0x6c737a81,
		0x888f969d,
		0xa4abb2b9,
		0xc0c7ced5,
		0xdce3eaf1,
		0xf8ff060d,
		0x141b2229,
		0x30373e45,
		0x4c535a61,
		0x686f767d,
		0x848b9299,
		0xa0a7aeb5,
		0xbcc3cad1,
		0xd8dfe6ed,
		0xf4fb0209,
		0x10171e25,
		0x2c333a41,
		0x484f565d,
		0x646b7279
	];

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint T(uint b)
	{
		b = SubByte(b);
		return b ^ b.RotateLeft(2) ^ b.RotateLeft(10) ^ b.RotateLeft(18) ^ b.RotateLeft(24);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint L1(uint b)
	{
		return b ^ b.RotateLeft(13) ^ b.RotateLeft(23);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint SubByte(uint a)
	{
		uint b0 = S[(byte)(a >> 24)];
		uint b1 = S[(byte)(a >> 16 & 0xFF)];
		uint b2 = S[(byte)(a >> 8 & 0xFF)];
		byte b3 = S[(byte)(a & 0xFF)];

		return b0 << 24 | b1 << 16 | b2 << 8 | b3;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void InitRoundKeys(ReadOnlySpan<byte> key, Span<uint> rk)
	{
		uint k0 = BinaryPrimitives.ReadUInt32BigEndian(key.Slice(0 * 4)) ^ 0xa3b1bac6;
		uint k1 = BinaryPrimitives.ReadUInt32BigEndian(key.Slice(1 * 4)) ^ 0x56aa3350;
		uint k2 = BinaryPrimitives.ReadUInt32BigEndian(key.Slice(2 * 4)) ^ 0x677d9197;
		uint k3 = BinaryPrimitives.ReadUInt32BigEndian(key.Slice(3 * 4)) ^ 0xb27022dc;

		for (int i = 0; i < 32; i += 4)
		{
			k0 ^= L1(SubByte(k1 ^ k2 ^ k3 ^ Ck[i + 0]));
			rk[i + 0] = k0;

			k1 ^= L1(SubByte(k2 ^ k3 ^ k0 ^ Ck[i + 1]));
			rk[i + 1] = k1;

			k2 ^= L1(SubByte(k3 ^ k0 ^ k1 ^ Ck[i + 2]));
			rk[i + 2] = k2;

			k3 ^= L1(SubByte(k0 ^ k1 ^ k2 ^ Ck[i + 3]));
			rk[i + 3] = k3;
		}
	}

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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> AesX86EncryptLast(in Vector256<byte> x, in Vector256<byte> roundKey)
	{
		Vector128<byte> t = AesX86.EncryptLast(x.GetUpper(), roundKey.GetUpper());
		return AesX86.EncryptLast(x.GetLower(), roundKey.GetLower()).ToVector256Unsafe().WithUpper(t);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static VectorBuffer16 Encrypt(scoped in ReadOnlySpan<uint> rk, scoped in VectorBuffer16 source)
	{
		uint u0 = BinaryPrimitives.ReverseEndianness(source.U0);
		uint u1 = BinaryPrimitives.ReverseEndianness(source.U1);
		uint u2 = BinaryPrimitives.ReverseEndianness(source.U2);
		uint u3 = BinaryPrimitives.ReverseEndianness(source.U3);

		for (int i = 0; i < 32; i += 4)
		{
			u0 ^= T(u1 ^ u2 ^ u3 ^ rk[i + 0]);
			u1 ^= T(u0 ^ u2 ^ u3 ^ rk[i + 1]);
			u2 ^= T(u0 ^ u1 ^ u3 ^ rk[i + 2]);
			u3 ^= T(u0 ^ u1 ^ u2 ^ rk[i + 3]);
		}

		Unsafe.SkipInit(out VectorBuffer16 r);
		r.U0 = BinaryPrimitives.ReverseEndianness(u3);
		r.U1 = BinaryPrimitives.ReverseEndianness(u2);
		r.U2 = BinaryPrimitives.ReverseEndianness(u1);
		r.U3 = BinaryPrimitives.ReverseEndianness(u0);

		return r;
	}

	/// <summary>
	/// https://github.com/mjosaarinen/sm4ni/blob/master/sm4ni.c
	/// </summary>
	public static void Encrypt4(ReadOnlySpan<uint> rk, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		ref byte dstRef = ref destination.GetReference();
		ref byte sourceRef = ref source.GetReference();

		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> shr = Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);

		ref readonly Vector128<byte> s0 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 0 * 16));
		ref readonly Vector128<byte> s1 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 1 * 16));
		ref readonly Vector128<byte> s2 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 2 * 16));
		ref readonly Vector128<byte> s3 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 3 * 16));

		Vector128<byte> t0 = s0.ReverseEndianness32();
		Vector128<byte> t1 = s1.ReverseEndianness32();
		Vector128<byte> t2 = s2.ReverseEndianness32();
		Vector128<byte> t3 = s3.ReverseEndianness32();

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

		t0 = t0.ReverseEndianness128();
		t1 = t1.ReverseEndianness128();
		t2 = t2.ReverseEndianness128();
		t3 = t3.ReverseEndianness128();

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 0 * 16), t0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 1 * 16), t1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 2 * 16), t2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 3 * 16), t3);
	}

	public static void Encrypt8(ReadOnlySpan<uint> rk, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		ref byte dstRef = ref destination.GetReference();
		ref byte sourceRef = ref source.GetReference();

		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> shr = Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);

		ref readonly Vector128<byte> s0 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 0 * 16));
		ref readonly Vector128<byte> s1 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 1 * 16));
		ref readonly Vector128<byte> s2 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 2 * 16));
		ref readonly Vector128<byte> s3 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 3 * 16));
		ref readonly Vector128<byte> s4 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 4 * 16));
		ref readonly Vector128<byte> s5 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 5 * 16));
		ref readonly Vector128<byte> s6 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 6 * 16));
		ref readonly Vector128<byte> s7 = ref Unsafe.As<byte, Vector128<byte>>(ref Unsafe.Add(ref sourceRef, 7 * 16));

		Vector128<byte> a0 = s0.ReverseEndianness32();
		Vector128<byte> a1 = s1.ReverseEndianness32();
		Vector128<byte> a2 = s2.ReverseEndianness32();
		Vector128<byte> a3 = s3.ReverseEndianness32();
		Vector128<byte> b0 = s4.ReverseEndianness32();
		Vector128<byte> b1 = s5.ReverseEndianness32();
		Vector128<byte> b2 = s6.ReverseEndianness32();
		Vector128<byte> b3 = s7.ReverseEndianness32();

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

		a0 = a0.ReverseEndianness128();
		a1 = a1.ReverseEndianness128();
		a2 = a2.ReverseEndianness128();
		a3 = a3.ReverseEndianness128();
		b0 = b0.ReverseEndianness128();
		b1 = b1.ReverseEndianness128();
		b2 = b2.ReverseEndianness128();
		b3 = b3.ReverseEndianness128();

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 0 * 16), a0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 1 * 16), a1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 2 * 16), a2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 3 * 16), a3);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 4 * 16), b0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 5 * 16), b1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 6 * 16), b2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref dstRef, 7 * 16), b3);
	}

	public static void Encrypt16(ReadOnlySpan<uint> rk, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		ref byte dstRef = ref destination.GetReference();
		ref byte sourceRef = ref source.GetReference();

		Vector256<byte> c0f = Vector256.Create((byte)0x0F);
		Vector256<byte> vshr = Vector256.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3, 16, 29, 26, 23, 20, 17, 30, 27, 24, 21, 18, 31, 28, 25, 22, 19);

		ref readonly Vector256<byte> s0 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 0 * 32));
		ref readonly Vector256<byte> s1 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 1 * 32));
		ref readonly Vector256<byte> s2 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 2 * 32));
		ref readonly Vector256<byte> s3 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 3 * 32));
		ref readonly Vector256<byte> s4 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 4 * 32));
		ref readonly Vector256<byte> s5 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 5 * 32));
		ref readonly Vector256<byte> s6 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 6 * 32));
		ref readonly Vector256<byte> s7 = ref Unsafe.As<byte, Vector256<byte>>(ref Unsafe.Add(ref sourceRef, 7 * 32));

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
			x0 = AesX86EncryptLast(x0, c0f);
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
			x1 = AesX86EncryptLast(x1, c0f);
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
