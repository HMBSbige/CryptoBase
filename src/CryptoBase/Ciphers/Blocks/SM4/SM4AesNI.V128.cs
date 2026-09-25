using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly partial struct SM4AesNI
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PreTransform(ref Vector128<byte> x)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> m1l = Vector128.Create(PreAffineLow0, PreAffineLow1).AsByte();
		Vector128<byte> m1h = Vector128.Create(PreAffineHigh0, PreAffineHigh1).AsByte();
		Vector128<byte> t = x & c0f;
		x &= ~c0f;
		x = (x.AsUInt32() >>> 4).AsByte();
		t = Ssse3.Shuffle(m1l, t);
		x = Ssse3.Shuffle(m1h, x);
		x ^= t;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PostTransform(ref Vector128<byte> x)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> m2l = Vector128.Create(PostAffineLow0, PostAffineLow1).AsByte();
		Vector128<byte> m2h = Vector128.Create(PostAffineHigh0, PostAffineHigh1).AsByte();
		Vector128<byte> t = ~x & c0f;
		x = (x.AsUInt32() >>> 4).AsByte();
		x &= c0f;

		t = Ssse3.Shuffle(m2l, t);
		x = Ssse3.Shuffle(m2h, x);
		x ^= t;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseShiftRowsAndLinearTransform(ref Vector128<byte> x, Vector128<byte> shr)
	{
		x = Ssse3.Shuffle(x, shr);

		x = SM4Linear.Transform(x.AsUInt32()).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ref Vector128<byte> r0, ref Vector128<byte> r1, ref Vector128<byte> r2, ref Vector128<byte> r3, Vector128<byte> key, Vector128<byte> c0f, Vector128<byte> shr)
	{
		Vector128<byte> x = key ^ r1 ^ r2 ^ r3;

		PreTransform(ref x);
		x = AesX86.EncryptLast(x, c0f);
		PostTransform(ref x);

		InverseShiftRowsAndLinearTransform(ref x, shr);

		r0 ^= x;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round2V128
	(
		ref Vector128<byte> x0, ref Vector128<byte> x1, ref Vector128<byte> x2, ref Vector128<byte> x3,
		ref Vector128<byte> y0, ref Vector128<byte> y1, ref Vector128<byte> y2, ref Vector128<byte> y3,
		Vector128<byte> key, Vector128<byte> c0f, Vector128<byte> shr
	)
	{
		if (!Avx.IsSupported)
		{
			Round(ref x0, ref x1, ref x2, ref x3, key, c0f, shr);
			Round(ref y0, ref y1, ref y2, ref y3, key, c0f, shr);
			return;
		}

		Vector128<byte> x = key ^ x1 ^ x2 ^ x3;
		Vector128<byte> y = key ^ y1 ^ y2 ^ y3;
		PreTransform(ref x);
		PreTransform(ref y);
		x = AesX86.EncryptLast(x, c0f);
		y = AesX86.EncryptLast(y, c0f);
		PostTransform(ref x);
		PostTransform(ref y);
		InverseShiftRowsAndLinearTransform(ref x, shr);
		InverseShiftRowsAndLinearTransform(ref y, shr);

		x0 ^= x;
		y0 ^= y;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process4V128(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load4X86(count, ref source, 0, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3);
		Rounds4V128(ref rk, ref v0, ref v1, ref v2, ref v3);
		SM4Layout.Store4X86(count, ref destination, 0, v0, v1, v2, v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds4V128(ref uint rk, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> shr = SM4AesConstants.InverseShiftRows;

		for (int i = 0; i < 32; i += 4)
		{
			Round(ref v0, ref v1, ref v2, ref v3, Vector128.Create(Unsafe.Add(ref rk, i)).AsByte(), c0f, shr);
			Round(ref v1, ref v2, ref v3, ref v0, Vector128.Create(Unsafe.Add(ref rk, i + 1)).AsByte(), c0f, shr);
			Round(ref v2, ref v3, ref v0, ref v1, Vector128.Create(Unsafe.Add(ref rk, i + 2)).AsByte(), c0f, shr);
			Round(ref v3, ref v0, ref v1, ref v2, Vector128.Create(Unsafe.Add(ref rk, i + 3)).AsByte(), c0f, shr);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process8V128(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load4X86(count, ref source, 0, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3);
		SM4Layout.Load4X86(count - 4, ref source, 64, out Vector128<byte> v4, out Vector128<byte> v5, out Vector128<byte> v6, out Vector128<byte> v7);
		Rounds8V128(ref rk, ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		SM4Layout.Store4X86(count, ref destination, 0, v0, v1, v2, v3);
		SM4Layout.Store4X86(count - 4, ref destination, 64, v4, v5, v6, v7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds8V128
	(
		ref uint rk,
		ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3,
		ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7
	)
	{
		Vector128<byte> c0f = Vector128.Create((byte)0x0F);
		Vector128<byte> shr = SM4AesConstants.InverseShiftRows;

		for (int i = 0; i < 32; ++i)
		{
			Round2V128(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, Vector128.Create(Unsafe.Add(ref rk, i)).AsByte(), c0f, shr);

			Vector128<byte> t0 = v0;
			Vector128<byte> t4 = v4;
			v0 = v1;
			v4 = v5;
			v1 = v2;
			v5 = v6;
			v2 = v3;
			v6 = v7;
			v3 = t0;
			v7 = t4;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> Substitute(Vector128<byte> x)
	{
		PreTransform(ref x);
		x = AesX86.EncryptLast(x, Vector128.Create((byte)0x0F));
		PostTransform(ref x);
		return Ssse3.Shuffle(x, SM4AesConstants.InverseShiftRows);
	}
}
