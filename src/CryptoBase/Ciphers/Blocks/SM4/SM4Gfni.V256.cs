namespace CryptoBase.Ciphers.Blocks.SM4;

internal readonly partial struct SM4Gfni
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<byte> Substitute(Vector256<byte> x)
	{
		x = Gfni.V256.GaloisFieldAffineTransform(x, Vector256.Create(PreAffine).AsByte(), PreConstant);
		return Gfni.V256.GaloisFieldAffineTransformInverse(x, Vector256.Create(PostAffine).AsByte(), PostConstant);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ref Vector256<byte> r0, Vector256<byte> r1, Vector256<byte> r2, Vector256<byte> r3, Vector256<byte> key)
	{
		Vector256<byte> x = Substitute(key ^ r1 ^ r2 ^ r3);
		r0 = SM4Linear.XorTransform(r0.AsUInt32(), x.AsUInt32()).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void RoundLookahead(ref Vector256<byte> r0, Vector256<byte> r2, Vector256<byte> r3, ref Vector256<byte> input, Vector256<byte> nextKey)
	{
		Vector256<uint> prefix = (r0 ^ r2 ^ r3 ^ nextKey).AsUInt32();
		Vector256<uint> x = Substitute(input).AsUInt32();
		Vector256<uint> p = x ^ x.RotateLeftUInt32(2) ^ x.RotateLeftUInt32(10);
		Vector256<uint> q = x.RotateLeftUInt32(18) ^ x.RotateLeftUInt32(24);
		input = (prefix ^ p ^ q).AsByte();
		r0 = (r0.AsUInt32() ^ p ^ q).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process8V256(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load8X86(count, ref source, 0, out Vector256<byte> v0, out Vector256<byte> v1, out Vector256<byte> v2, out Vector256<byte> v3);

		if (Avx512F.VL.IsSupported)
		{
			Vector256<byte> input = Vector256.Create(rk).AsByte() ^ v1 ^ v2 ^ v3;

			for (int i = 0; i < 28; i += 4)
			{
				RoundLookahead(ref v0, v2, v3, ref input, Vector256.Create(Unsafe.Add(ref rk, i + 1)).AsByte());
				RoundLookahead(ref v1, v3, v0, ref input, Vector256.Create(Unsafe.Add(ref rk, i + 2)).AsByte());
				RoundLookahead(ref v2, v0, v1, ref input, Vector256.Create(Unsafe.Add(ref rk, i + 3)).AsByte());
				RoundLookahead(ref v3, v1, v2, ref input, Vector256.Create(Unsafe.Add(ref rk, i + 4)).AsByte());
			}

			RoundLookahead(ref v0, v2, v3, ref input, Vector256.Create(Unsafe.Add(ref rk, 29)).AsByte());
			RoundLookahead(ref v1, v3, v0, ref input, Vector256.Create(Unsafe.Add(ref rk, 30)).AsByte());
			RoundLookahead(ref v2, v0, v1, ref input, Vector256.Create(Unsafe.Add(ref rk, 31)).AsByte());
			v3 = SM4Linear.XorTransform(v3.AsUInt32(), Substitute(input).AsUInt32()).AsByte();
		}
		else
		{
			for (int i = 0; i < 32; i += 4)
			{
				Round(ref v0, v1, v2, v3, Vector256.Create(Unsafe.Add(ref rk, i)).AsByte());
				Round(ref v1, v2, v3, v0, Vector256.Create(Unsafe.Add(ref rk, i + 1)).AsByte());
				Round(ref v2, v3, v0, v1, Vector256.Create(Unsafe.Add(ref rk, i + 2)).AsByte());
				Round(ref v3, v0, v1, v2, Vector256.Create(Unsafe.Add(ref rk, i + 3)).AsByte());
			}
		}

		SM4Layout.Store8X86(count, ref destination, 0, v0, v1, v2, v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Process16V256(int count, ref uint rk, ref byte source, ref byte destination)
	{
		SM4Layout.Load8X86(count, ref source, 0, out Vector256<byte> a0, out Vector256<byte> a1, out Vector256<byte> a2, out Vector256<byte> a3);
		SM4Layout.Load8X86(count - 8, ref source, 128, out Vector256<byte> b0, out Vector256<byte> b1, out Vector256<byte> b2, out Vector256<byte> b3);

		for (int i = 0; i < 32; i += 4)
		{
			Vector256<byte> key = Vector256.Create(Unsafe.Add(ref rk, i)).AsByte();
			Round(ref a0, a1, a2, a3, key);
			Round(ref b0, b1, b2, b3, key);

			key = Vector256.Create(Unsafe.Add(ref rk, i + 1)).AsByte();
			Round(ref a1, a2, a3, a0, key);
			Round(ref b1, b2, b3, b0, key);

			key = Vector256.Create(Unsafe.Add(ref rk, i + 2)).AsByte();
			Round(ref a2, a3, a0, a1, key);
			Round(ref b2, b3, b0, b1, key);

			key = Vector256.Create(Unsafe.Add(ref rk, i + 3)).AsByte();
			Round(ref a3, a0, a1, a2, key);
			Round(ref b3, b0, b1, b2, key);
		}

		SM4Layout.Store8X86(count, ref destination, 0, a0, a1, a2, a3);
		SM4Layout.Store8X86(count - 8, ref destination, 128, b0, b1, b2, b3);
	}
}
