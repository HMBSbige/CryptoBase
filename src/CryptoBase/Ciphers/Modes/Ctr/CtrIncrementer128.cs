namespace CryptoBase.Ciphers.Modes.Ctr;

internal readonly struct CtrIncrementer128 : ICtrIncrementer
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> Inc(Vector128<byte> counter)
	{
		return counter.IncUInt128LE();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add01(Vector256<byte> counter)
	{
		return counter.AddUInt128LE01();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add22(Vector256<byte> counter)
	{
		return counter.AddUInt128LE22();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add0123(Vector512<byte> counter)
	{
		return counter.AddUInt128LE0123();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add4444(Vector512<byte> counter)
	{
		return counter.AddUInt128LE4444();
	}
}
