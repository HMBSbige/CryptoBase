namespace CryptoBase.Ciphers.Modes;

// Counters use little-endian byte order after reversing the external big-endian block.
internal interface ICtrIncrementer
{
	static abstract Vector128<byte> Inc(Vector128<byte> counter);

	static abstract Vector256<byte> Add01(Vector256<byte> counter);

	static abstract Vector256<byte> Add22(Vector256<byte> counter);

	static abstract Vector512<byte> Add0123(Vector512<byte> counter);

	static abstract Vector512<byte> Add4444(Vector512<byte> counter);
}

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

// Only the low 32 bits advance; overflow does not carry into the upper 96 bits.
internal readonly struct CtrIncrementer32 : ICtrIncrementer
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> Inc(Vector128<byte> counter)
	{
		return counter.IncUInt32LE();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add01(Vector256<byte> counter)
	{
		return counter.AddUInt32LE01();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add22(Vector256<byte> counter)
	{
		return counter.AddUInt32LE22();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add0123(Vector512<byte> counter)
	{
		return counter.AddUInt32LE0123();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add4444(Vector512<byte> counter)
	{
		return counter.AddUInt32LE4444();
	}
}
