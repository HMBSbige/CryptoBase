namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

/// <summary>
/// CTR counter increment strategy. All vector methods take and return counters with byte order already reversed (big-endian counter converted to little-endian).
/// </summary>
public interface ICtrIncrementer
{
	static abstract Vector128<byte> Inc(Vector128<byte> counter);

	static abstract void IncSoftware(ref VectorBuffer16 counter);

	static abstract Vector256<byte> Add01(Vector256<byte> counter);

	static abstract Vector256<byte> Add22(Vector256<byte> counter);

	static abstract Vector512<byte> Add0123(Vector512<byte> counter);

	static abstract Vector512<byte> Add4444(Vector512<byte> counter);
}

/// <summary>
/// Full 128-bit counter (standard CTR).
/// </summary>
public readonly struct CtrIncrementer128 : ICtrIncrementer
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> Inc(Vector128<byte> counter)
	{
		return counter.IncUInt128Le();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void IncSoftware(ref VectorBuffer16 counter)
	{
		if (BitConverter.IsLittleEndian)
		{
			counter.U128 = BinaryPrimitives.ReverseEndianness(counter.U128) + 1;
			counter.U128 = BinaryPrimitives.ReverseEndianness(counter.U128);
		}
		else
		{
			++counter.U128;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add01(Vector256<byte> counter)
	{
		return counter.AddUInt128Le01();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add22(Vector256<byte> counter)
	{
		return counter.AddUInt128Le22();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add0123(Vector512<byte> counter)
	{
		return counter.AddUInt128Le0123();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add4444(Vector512<byte> counter)
	{
		return counter.AddUInt128Le4444();
	}
}

/// <summary>
/// Low 32-bit counter only (GCM semantics).
/// </summary>
public readonly struct CtrIncrementer32 : ICtrIncrementer
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> Inc(Vector128<byte> counter)
	{
		return counter.IncUInt32Le();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void IncSoftware(ref VectorBuffer16 counter)
	{
		if (BitConverter.IsLittleEndian)
		{
			counter.U3 = BinaryPrimitives.ReverseEndianness(counter.U3) + 1;
			counter.U3 = BinaryPrimitives.ReverseEndianness(counter.U3);
		}
		else
		{
			++counter.U3;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add01(Vector256<byte> counter)
	{
		return counter.AddUInt32Le01();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add22(Vector256<byte> counter)
	{
		return counter.AddUInt32Le22();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add0123(Vector512<byte> counter)
	{
		return counter.AddUInt32Le0123();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add4444(Vector512<byte> counter)
	{
		return counter.AddUInt32Le4444();
	}
}
