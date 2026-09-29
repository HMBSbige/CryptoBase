namespace CryptoBase.Ciphers.Modes.Ctr;

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
