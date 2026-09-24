using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.Ciphers.Blocks.SM4;

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

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private void InverseShiftRowsAndLinearTransform(Vector256<byte> shr)
		{
			x = Avx2.Shuffle(x, shr);

			Vector256<byte> t = x ^ x.RotateLeftUInt32(8) ^ x.RotateLeftUInt32(16);
			t = t.RotateLeftUInt32(2);
			x = x ^ t ^ x.RotateLeftUInt32(24);
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
		x.InverseShiftRowsAndLinearTransform(vshr);

		x ^= r0;
		r0 = r1;
		r1 = r2;
		r2 = r3;
		r3 = x;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round2V256
	(
		ref Vector256<byte> x0, ref Vector256<byte> x1, ref Vector256<byte> x2, ref Vector256<byte> x3,
		ref Vector256<byte> y0, ref Vector256<byte> y1, ref Vector256<byte> y2, ref Vector256<byte> y3,
		Vector256<byte> key, Vector256<byte> c0f, Vector256<byte> shr
	)
	{
		if (Avx512F.VL.IsSupported)
		{
			Round(ref x0, ref x1, ref x2, ref x3, key, c0f, shr);
			Round(ref y0, ref y1, ref y2, ref y3, key, c0f, shr);
			return;
		}

		Vector256<byte> x = key ^ x1 ^ x2 ^ x3;
		Vector256<byte> y = key ^ y1 ^ y2 ^ y3;
		x.PreTransform();
		y.PreTransform();
		x = AesX86EncryptLast(x, c0f);
		y = AesX86EncryptLast(y, c0f);
		x.PostTransform();
		y.PostTransform();
		x.InverseShiftRowsAndLinearTransform(shr);
		y.InverseShiftRowsAndLinearTransform(shr);

		x ^= x0;
		y ^= y0;
		x0 = x1;
		y0 = y1;
		x1 = x2;
		y1 = y2;
		x2 = x3;
		y2 = y3;
		x3 = x;
		y3 = y;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Process8V256(ReadOnlySpan<uint> rk, ref byte source, ref byte destination)
	{
		Vector256<byte> c0f = Vector256.Create((byte)0x0F);
		Vector256<byte> vshr = Vector256.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3, 16, 29, 26, 23, 20, 17, 30, 27, 24, 21, 18, 31, 28, 25, 22, 19);

		Vector256<byte> v0 = Vector256.LoadUnsafe(ref source, 0).ReverseEndianness32();
		Vector256<byte> v1 = Vector256.LoadUnsafe(ref source, 32).ReverseEndianness32();
		Vector256<byte> v2 = Vector256.LoadUnsafe(ref source, 64).ReverseEndianness32();
		Vector256<byte> v3 = Vector256.LoadUnsafe(ref source, 96).ReverseEndianness32();

		Transpose(ref v0, ref v1, ref v2, ref v3);

		foreach (uint key in rk)
		{
			Round(ref v0, ref v1, ref v2, ref v3, Vector256.Create(key).AsByte(), c0f, vshr);
		}

		Transpose(ref v0, ref v1, ref v2, ref v3);

		v0 = v0.ReverseEndianness128();
		v1 = v1.ReverseEndianness128();
		v2 = v2.ReverseEndianness128();
		v3 = v3.ReverseEndianness128();

		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 32);
		v2.StoreUnsafe(ref destination, 64);
		v3.StoreUnsafe(ref destination, 96);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Process16V256(ReadOnlySpan<uint> rk, ref byte source, ref byte destination)
	{
		Vector256<byte> c0f = Vector256.Create((byte)0x0F);
		Vector256<byte> vshr = Vector256.Create((byte)0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3, 16, 29, 26, 23, 20, 17, 30, 27, 24, 21, 18, 31, 28, 25, 22, 19);

		Vector256<byte> v0 = Vector256.LoadUnsafe(ref source, 0).ReverseEndianness32();
		Vector256<byte> v1 = Vector256.LoadUnsafe(ref source, 32).ReverseEndianness32();
		Vector256<byte> v2 = Vector256.LoadUnsafe(ref source, 64).ReverseEndianness32();
		Vector256<byte> v3 = Vector256.LoadUnsafe(ref source, 96).ReverseEndianness32();
		Vector256<byte> v4 = Vector256.LoadUnsafe(ref source, 128).ReverseEndianness32();
		Vector256<byte> v5 = Vector256.LoadUnsafe(ref source, 160).ReverseEndianness32();
		Vector256<byte> v6 = Vector256.LoadUnsafe(ref source, 192).ReverseEndianness32();
		Vector256<byte> v7 = Vector256.LoadUnsafe(ref source, 224).ReverseEndianness32();

		Transpose(ref v0, ref v1, ref v2, ref v3);
		Transpose(ref v4, ref v5, ref v6, ref v7);

		foreach (uint key in rk)
		{
			Vector256<byte> vKey = Vector256.Create(key).AsByte();

			Round2V256(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, vKey, c0f, vshr);
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
		v1.StoreUnsafe(ref destination, 32);
		v2.StoreUnsafe(ref destination, 64);
		v3.StoreUnsafe(ref destination, 96);
		v4.StoreUnsafe(ref destination, 128);
		v5.StoreUnsafe(ref destination, 160);
		v6.StoreUnsafe(ref destination, 192);
		v7.StoreUnsafe(ref destination, 224);
	}
}
