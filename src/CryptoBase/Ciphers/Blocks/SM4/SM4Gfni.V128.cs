namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly partial struct SM4Gfni
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<byte> Substitute(Vector128<byte> x)
	{
		x = Gfni.GaloisFieldAffineTransform(x, Vector128.Create(PreAffine).AsByte(), PreConstant);
		return Gfni.GaloisFieldAffineTransformInverse(x, Vector128.Create(PostAffine).AsByte(), PostConstant);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ref Vector128<byte> r0, Vector128<byte> r1, Vector128<byte> r2, Vector128<byte> r3, Vector128<byte> key)
	{
		Vector128<byte> x = Substitute(key ^ r1 ^ r2 ^ r3);
		r0 = SM4Linear.XorTransform(r0.AsUInt32(), x.AsUInt32()).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void RoundLookahead(ref Vector128<byte> r0, Vector128<byte> r2, Vector128<byte> r3, ref Vector128<byte> input, Vector128<byte> nextKey)
	{
		Vector128<uint> prefix = (r0 ^ r2 ^ r3 ^ nextKey).AsUInt32();
		Vector128<uint> x = Substitute(input).AsUInt32();
		Vector128<uint> p = x ^ x.RotateLeftUInt32(2) ^ x.RotateLeftUInt32(10);
		Vector128<uint> q = x.RotateLeftUInt32(18) ^ x.RotateLeftUInt32(24);
		input = (prefix ^ p ^ q).AsByte();
		r0 = (r0.AsUInt32() ^ p ^ q).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process4V128(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load4X86(count, ref source, 0, out Vector128<byte> v0, out Vector128<byte> v1, out Vector128<byte> v2, out Vector128<byte> v3);

		if (Avx512F.VL.IsSupported)
		{
			Vector128<byte> input = Vector128.Create(rk).AsByte() ^ v1 ^ v2 ^ v3;

			for (int i = 0; i < 28; i += 4)
			{
				RoundLookahead(ref v0, v2, v3, ref input, Vector128.Create(Unsafe.Add(ref rk, i + 1)).AsByte());
				RoundLookahead(ref v1, v3, v0, ref input, Vector128.Create(Unsafe.Add(ref rk, i + 2)).AsByte());
				RoundLookahead(ref v2, v0, v1, ref input, Vector128.Create(Unsafe.Add(ref rk, i + 3)).AsByte());
				RoundLookahead(ref v3, v1, v2, ref input, Vector128.Create(Unsafe.Add(ref rk, i + 4)).AsByte());
			}

			RoundLookahead(ref v0, v2, v3, ref input, Vector128.Create(Unsafe.Add(ref rk, 29)).AsByte());
			RoundLookahead(ref v1, v3, v0, ref input, Vector128.Create(Unsafe.Add(ref rk, 30)).AsByte());
			RoundLookahead(ref v2, v0, v1, ref input, Vector128.Create(Unsafe.Add(ref rk, 31)).AsByte());
			v3 = SM4Linear.XorTransform(v3.AsUInt32(), Substitute(input).AsUInt32()).AsByte();
		}
		else
		{
			for (int i = 0; i < 32; i += 4)
			{
				Round(ref v0, v1, v2, v3, Vector128.Create(Unsafe.Add(ref rk, i)).AsByte());
				Round(ref v1, v2, v3, v0, Vector128.Create(Unsafe.Add(ref rk, i + 1)).AsByte());
				Round(ref v2, v3, v0, v1, Vector128.Create(Unsafe.Add(ref rk, i + 2)).AsByte());
				Round(ref v3, v0, v1, v2, Vector128.Create(Unsafe.Add(ref rk, i + 3)).AsByte());
			}
		}

		SM4Layout.Store4X86(count, ref destination, 0, v0, v1, v2, v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process8V128(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load4X86(count, ref source, 0, out Vector128<byte> a0, out Vector128<byte> a1, out Vector128<byte> a2, out Vector128<byte> a3);
		SM4Layout.Load4X86(count - 4, ref source, 64, out Vector128<byte> b0, out Vector128<byte> b1, out Vector128<byte> b2, out Vector128<byte> b3);

		for (int i = 0; i < 32; i += 4)
		{
			Vector128<byte> key = Vector128.Create(Unsafe.Add(ref rk, i)).AsByte();
			Round(ref a0, a1, a2, a3, key);
			Round(ref b0, b1, b2, b3, key);

			key = Vector128.Create(Unsafe.Add(ref rk, i + 1)).AsByte();
			Round(ref a1, a2, a3, a0, key);
			Round(ref b1, b2, b3, b0, key);

			key = Vector128.Create(Unsafe.Add(ref rk, i + 2)).AsByte();
			Round(ref a2, a3, a0, a1, key);
			Round(ref b2, b3, b0, b1, key);

			key = Vector128.Create(Unsafe.Add(ref rk, i + 3)).AsByte();
			Round(ref a3, a0, a1, a2, key);
			Round(ref b3, b0, b1, b2, key);
		}

		SM4Layout.Store4X86(count, ref destination, 0, a0, a1, a2, a3);
		SM4Layout.Store4X86(count - 4, ref destination, 64, b0, b1, b2, b3);
	}
}
