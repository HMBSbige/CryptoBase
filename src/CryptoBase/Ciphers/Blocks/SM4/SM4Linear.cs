namespace CryptoBase.Ciphers.Blocks.SM4;

internal static class SM4Linear
{
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
}
