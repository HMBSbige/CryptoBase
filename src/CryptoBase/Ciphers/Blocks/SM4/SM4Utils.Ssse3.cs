using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.Ciphers.Blocks.SM4;

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
			t = Ssse3.Shuffle(m1l, t);
			x = Ssse3.Shuffle(m1h, x);
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

			t = Ssse3.Shuffle(m2l, t);
			x = Ssse3.Shuffle(m2h, x);
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
		x = Ssse3.Shuffle(x, shr);

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

	// https://github.com/mjosaarinen/sm4ni/blob/master/sm4ni.c
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Process4V128(ReadOnlySpan<uint> rk, ref byte source, ref byte destination)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> shr = Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);

		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0).ReverseEndianness32();
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16).ReverseEndianness32();
		Vector128<byte> v2 = Vector128.LoadUnsafe(ref source, 32).ReverseEndianness32();
		Vector128<byte> v3 = Vector128.LoadUnsafe(ref source, 48).ReverseEndianness32();

		Transpose(ref v0, ref v1, ref v2, ref v3);

		foreach (uint key in rk)
		{
			Round(ref v0, ref v1, ref v2, ref v3, Vector128.Create(key).AsByte(), c0f, shr);
		}

		Transpose(ref v0, ref v1, ref v2, ref v3);

		v0 = v0.ReverseEndianness128();
		v1 = v1.ReverseEndianness128();
		v2 = v2.ReverseEndianness128();
		v3 = v3.ReverseEndianness128();

		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		v2.StoreUnsafe(ref destination, 32);
		v3.StoreUnsafe(ref destination, 48);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Process8V128(ReadOnlySpan<uint> rk, ref byte source, ref byte destination)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> shr = Vector128.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3);

		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0).ReverseEndianness32();
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16).ReverseEndianness32();
		Vector128<byte> v2 = Vector128.LoadUnsafe(ref source, 32).ReverseEndianness32();
		Vector128<byte> v3 = Vector128.LoadUnsafe(ref source, 48).ReverseEndianness32();
		Vector128<byte> v4 = Vector128.LoadUnsafe(ref source, 64).ReverseEndianness32();
		Vector128<byte> v5 = Vector128.LoadUnsafe(ref source, 80).ReverseEndianness32();
		Vector128<byte> v6 = Vector128.LoadUnsafe(ref source, 96).ReverseEndianness32();
		Vector128<byte> v7 = Vector128.LoadUnsafe(ref source, 112).ReverseEndianness32();

		Transpose(ref v0, ref v1, ref v2, ref v3);
		Transpose(ref v4, ref v5, ref v6, ref v7);

		foreach (uint key in rk)
		{
			Vector128<byte> vKey = Vector128.Create(key).AsByte();

			Round(ref v0, ref v1, ref v2, ref v3, vKey, c0f, shr);
			Round(ref v4, ref v5, ref v6, ref v7, vKey, c0f, shr);
		}

		Transpose(ref v0, ref v1, ref v2, ref v3);
		Transpose(ref v4, ref v5, ref v6, ref v7);

		v0 = v0.ReverseEndianness128();
		v1 = v1.ReverseEndianness128();
		v2 = v2.ReverseEndianness128();
		v3 = v3.ReverseEndianness128();
		v4 = v4.ReverseEndianness128();
		v5 = v5.ReverseEndianness128();
		v6 = v6.ReverseEndianness128();
		v7 = v7.ReverseEndianness128();

		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		v2.StoreUnsafe(ref destination, 32);
		v3.StoreUnsafe(ref destination, 48);
		v4.StoreUnsafe(ref destination, 64);
		v5.StoreUnsafe(ref destination, 80);
		v6.StoreUnsafe(ref destination, 96);
		v7.StoreUnsafe(ref destination, 112);
	}
}
