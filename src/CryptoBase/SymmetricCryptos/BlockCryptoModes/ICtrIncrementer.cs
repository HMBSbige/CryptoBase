namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

/// <summary>
/// CTR counter increment strategy. All vector methods take and return counters with byte order already reversed (big-endian counter converted to little-endian).
/// </summary>
public interface ICtrIncrementer
{
	/// <summary>Increments one counter by one.</summary>
	/// <param name="counter">The byte-reversed counter.</param>
	/// <returns>The incremented counter.</returns>
	static abstract Vector128<byte> Inc(Vector128<byte> counter);

	/// <summary>Increments one counter in place without SIMD intrinsics.</summary>
	/// <param name="counter">The counter in block byte order.</param>
	static abstract void IncSoftware(ref VectorBuffer16 counter);

	/// <summary>Adds 0 and 1 to the two counter lanes, respectively.</summary>
	/// <param name="counter">The byte-reversed counter lanes.</param>
	/// <returns>The adjusted counter lanes.</returns>
	static abstract Vector256<byte> Add01(Vector256<byte> counter);

	/// <summary>Adds 2 to both counter lanes.</summary>
	/// <param name="counter">The byte-reversed counter lanes.</param>
	/// <returns>The adjusted counter lanes.</returns>
	static abstract Vector256<byte> Add22(Vector256<byte> counter);

	/// <summary>Adds 0, 1, 2, and 3 to the four counter lanes, respectively.</summary>
	/// <param name="counter">The byte-reversed counter lanes.</param>
	/// <returns>The adjusted counter lanes.</returns>
	static abstract Vector512<byte> Add0123(Vector512<byte> counter);

	/// <summary>Adds 4 to all four counter lanes.</summary>
	/// <param name="counter">The byte-reversed counter lanes.</param>
	/// <returns>The adjusted counter lanes.</returns>
	static abstract Vector512<byte> Add4444(Vector512<byte> counter);
}

/// <summary>
/// Full 128-bit counter (standard CTR).
/// </summary>
public readonly struct CtrIncrementer128 : ICtrIncrementer
{
	/// <inheritdoc/>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> Inc(Vector128<byte> counter)
	{
		return counter.IncUInt128LE();
	}

	/// <inheritdoc/>
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

	/// <inheritdoc/>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add01(Vector256<byte> counter)
	{
		return counter.AddUInt128LE01();
	}

	/// <inheritdoc/>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add22(Vector256<byte> counter)
	{
		return counter.AddUInt128LE22();
	}

	/// <inheritdoc/>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add0123(Vector512<byte> counter)
	{
		return counter.AddUInt128LE0123();
	}

	/// <inheritdoc/>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add4444(Vector512<byte> counter)
	{
		return counter.AddUInt128LE4444();
	}
}

/// <summary>
/// Low 32-bit counter only (GCM semantics).
/// </summary>
public readonly struct CtrIncrementer32 : ICtrIncrementer
{
	/// <inheritdoc/>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector128<byte> Inc(Vector128<byte> counter)
	{
		return counter.IncUInt32LE();
	}

	/// <inheritdoc/>
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

	/// <inheritdoc/>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add01(Vector256<byte> counter)
	{
		return counter.AddUInt32LE01();
	}

	/// <inheritdoc/>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector256<byte> Add22(Vector256<byte> counter)
	{
		return counter.AddUInt32LE22();
	}

	/// <inheritdoc/>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add0123(Vector512<byte> counter)
	{
		return counter.AddUInt32LE0123();
	}

	/// <inheritdoc/>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static Vector512<byte> Add4444(Vector512<byte> counter)
	{
		return counter.AddUInt32LE4444();
	}
}
