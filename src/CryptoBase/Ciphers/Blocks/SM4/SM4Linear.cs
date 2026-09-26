namespace CryptoBase.Ciphers.Blocks.SM4;

internal static class SM4Linear
{
	// 0x96 selects a ^ b ^ c.
	// Explicit TernaryLogic keeps the XOR grouping that measured faster than equivalent ^ expressions.
	private const byte Xor3 = 0xF0 ^ 0xCC ^ 0xAA;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<uint> Transform(Vector128<uint> x)
	{
		Vector128<uint> t = x ^ x.RotateLeftUInt32(8) ^ x.RotateLeftUInt32(16);
		return x ^ t.RotateLeftUInt32(2) ^ x.RotateLeftUInt32(24);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<uint> Transform(Vector256<uint> x)
	{
		Vector256<uint> t = x ^ x.RotateLeftUInt32(8) ^ x.RotateLeftUInt32(16);
		return x ^ t.RotateLeftUInt32(2) ^ x.RotateLeftUInt32(24);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<uint> XorTransform(Vector128<uint> r, Vector128<uint> x)
	{
		if (Avx512F.VL.IsSupported)
		{
			Vector128<uint> left = r ^ x;
			Vector128<uint> right = Avx512F.VL.TernaryLogic(x.RotateLeftUInt32(2), x.RotateLeftUInt32(10), x.RotateLeftUInt32(18), Xor3);
			return Avx512F.VL.TernaryLogic(left, right, x.RotateLeftUInt32(24), Xor3);
		}

		Vector128<uint> t = x ^ x.RotateLeftUInt32(8) ^ x.RotateLeftUInt32(16);
		return r ^ x ^ x.RotateLeftUInt32(24) ^ t.RotateLeftUInt32(2);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector256<uint> XorTransform(Vector256<uint> r, Vector256<uint> x)
	{
		if (Avx512F.VL.IsSupported)
		{
			Vector256<uint> left = r ^ x;
			Vector256<uint> right = Avx512F.VL.TernaryLogic(x.RotateLeftUInt32(2), x.RotateLeftUInt32(10), x.RotateLeftUInt32(18), Xor3);
			return Avx512F.VL.TernaryLogic(left, right, x.RotateLeftUInt32(24), Xor3);
		}

		Vector256<uint> t = x ^ x.RotateLeftUInt32(8) ^ x.RotateLeftUInt32(16);
		return r ^ x ^ x.RotateLeftUInt32(24) ^ t.RotateLeftUInt32(2);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector512<uint> XorTransform(Vector512<uint> r, Vector512<uint> x)
	{
		Vector512<uint> left = r ^ x;
		Vector512<uint> right = Avx512F.TernaryLogic(x.RotateLeftUInt32(2), x.RotateLeftUInt32(10), x.RotateLeftUInt32(18), Xor3);
		return Avx512F.TernaryLogic(left, right, x.RotateLeftUInt32(24), Xor3);
	}
}
