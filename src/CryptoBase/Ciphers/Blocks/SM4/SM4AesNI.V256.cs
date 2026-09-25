using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly partial struct SM4AesNI
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PreTransform(ref Vector256<byte> x)
	{
		Vector256<byte> vc0f = Vector256.Create((byte)0x0F);
		Vector256<byte> vm1l = Vector256.Create(Vector128.Create(PreAffineLow0, PreAffineLow1)).AsByte();
		Vector256<byte> vm1h = Vector256.Create(Vector128.Create(PreAffineHigh0, PreAffineHigh1)).AsByte();
		Vector256<byte> t = x & vc0f;
		x &= ~vc0f;
		x = (x.AsUInt32() >>> 4).AsByte();

		t = Avx2.Shuffle(vm1l, t);
		x = Avx2.Shuffle(vm1h, x);
		x ^= t;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void PostTransform(ref Vector256<byte> x)
	{
		Vector256<byte> vc0f = Vector256.Create((byte)0x0F);
		Vector256<byte> vm2l = Vector256.Create(Vector128.Create(PostAffineLow0, PostAffineLow1)).AsByte();
		Vector256<byte> vm2h = Vector256.Create(Vector128.Create(PostAffineHigh0, PostAffineHigh1)).AsByte();
		Vector256<byte> t = ~x & vc0f;
		x = (x.AsUInt32() >>> 4).AsByte();
		x &= vc0f;

		t = Avx2.Shuffle(vm2l, t);
		x = Avx2.Shuffle(vm2h, x);
		x ^= t;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseShiftRowsAndLinearTransform(ref Vector256<byte> x, Vector256<byte> shr)
	{
		x = Avx2.Shuffle(x, shr);

		x = SM4Linear.Transform(x.AsUInt32()).AsByte();
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

		PreTransform(ref x);
		x = AesX86EncryptLast(x, c0f);
		PostTransform(ref x);
		InverseShiftRowsAndLinearTransform(ref x, vshr);

		r0 ^= x;
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
		PreTransform(ref x);
		PreTransform(ref y);
		x = AesX86EncryptLast(x, c0f);
		y = AesX86EncryptLast(y, c0f);
		PostTransform(ref x);
		PostTransform(ref y);
		InverseShiftRowsAndLinearTransform(ref x, shr);
		InverseShiftRowsAndLinearTransform(ref y, shr);

		x0 ^= x;
		y0 ^= y;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process8V256(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load8X86(count, ref source, 0, out Vector256<byte> v0, out Vector256<byte> v1, out Vector256<byte> v2, out Vector256<byte> v3);
		Rounds8V256(ref rk, ref v0, ref v1, ref v2, ref v3);
		SM4Layout.Store8X86(count, ref destination, 0, v0, v1, v2, v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds8V256(ref uint rk, ref Vector256<byte> v0, ref Vector256<byte> v1, ref Vector256<byte> v2, ref Vector256<byte> v3)
	{
		Vector256<byte> c0f = Vector256.Create((byte)0x0F);
		Vector256<byte> vshr = Vector256.Create(SM4AesConstants.InverseShiftRows);

		for (int i = 0; i < 32; i += 4)
		{
			Round(ref v0, ref v1, ref v2, ref v3, Vector256.Create(Unsafe.Add(ref rk, i)).AsByte(), c0f, vshr);
			Round(ref v1, ref v2, ref v3, ref v0, Vector256.Create(Unsafe.Add(ref rk, i + 1)).AsByte(), c0f, vshr);
			Round(ref v2, ref v3, ref v0, ref v1, Vector256.Create(Unsafe.Add(ref rk, i + 2)).AsByte(), c0f, vshr);
			Round(ref v3, ref v0, ref v1, ref v2, Vector256.Create(Unsafe.Add(ref rk, i + 3)).AsByte(), c0f, vshr);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process16V256(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load8X86(count, ref source, 0, out Vector256<byte> v0, out Vector256<byte> v1, out Vector256<byte> v2, out Vector256<byte> v3);
		SM4Layout.Load8X86(count - 8, ref source, 128, out Vector256<byte> v4, out Vector256<byte> v5, out Vector256<byte> v6, out Vector256<byte> v7);
		Rounds16V256(ref rk, ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		SM4Layout.Store8X86(count, ref destination, 0, v0, v1, v2, v3);
		SM4Layout.Store8X86(count - 8, ref destination, 128, v4, v5, v6, v7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Rounds16V256
	(
		ref uint rk,
		ref Vector256<byte> v0, ref Vector256<byte> v1, ref Vector256<byte> v2, ref Vector256<byte> v3,
		ref Vector256<byte> v4, ref Vector256<byte> v5, ref Vector256<byte> v6, ref Vector256<byte> v7
	)
	{
		Vector256<byte> c0f = Vector256.Create((byte)0x0F);
		Vector256<byte> vshr = Vector256.Create(SM4AesConstants.InverseShiftRows);

		if (Avx512F.VL.IsSupported)
		{
			for (int i = 0; i < 32; i += 4)
			{
				Round2V256(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, Vector256.Create(Unsafe.Add(ref rk, i)).AsByte(), c0f, vshr);
				Round2V256(ref v1, ref v2, ref v3, ref v0, ref v5, ref v6, ref v7, ref v4, Vector256.Create(Unsafe.Add(ref rk, i + 1)).AsByte(), c0f, vshr);
				Round2V256(ref v2, ref v3, ref v0, ref v1, ref v6, ref v7, ref v4, ref v5, Vector256.Create(Unsafe.Add(ref rk, i + 2)).AsByte(), c0f, vshr);
				Round2V256(ref v3, ref v0, ref v1, ref v2, ref v7, ref v4, ref v5, ref v6, Vector256.Create(Unsafe.Add(ref rk, i + 3)).AsByte(), c0f, vshr);
			}

			return;
		}

		for (int i = 0; i < 32; ++i)
		{
			Round2V256(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, Vector256.Create(Unsafe.Add(ref rk, i)).AsByte(), c0f, vshr);

			Vector256<byte> t0 = v0;
			Vector256<byte> t4 = v4;
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
	internal static Vector256<byte> Substitute(Vector256<byte> x)
	{
		PreTransform(ref x);
		x = AesX86EncryptLast(x, Vector256.Create((byte)0x0F));
		PostTransform(ref x);
		return Avx2.Shuffle(x, Vector256.Create(SM4AesConstants.InverseShiftRows));
	}
}
