namespace CryptoBase.Ciphers.Modes.Gcm;

internal struct GHashKey
{
	internal Vector128<byte> Value;
	private GHashKeyTable<GHashFourBlockPrecomputedKey>? _fourBlock;
	private GHashKeyTable<GHashVector128PrecomputedKey>? _vector128;
	private GHashKeyTable<GHashVector256PrecomputedKey>? _vector256;
	private GHashKeyTable<GHashVector512PrecomputedKey>? _vector512;

	internal static GHashKey Create(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, GHash.BlockSizeInBytes, nameof(key));
		return new GHashKey { Value = Vector128.LoadUnsafe(ref key.GetReference()) };
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashFourBlockPrecomputedKey> GetFourBlock()
	{
		return _fourBlock ?? InitializeFourBlock();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashVector128PrecomputedKey> GetVector128()
	{
		return _vector128 ?? InitializeVector128();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashVector256PrecomputedKey> GetVector256()
	{
		return _vector256 ?? InitializeVector256();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashVector512PrecomputedKey> GetVector512()
	{
		return _vector512 ?? InitializeVector512();
	}

	// Keep table construction out of the warm callers' stack frames.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashFourBlockPrecomputedKey> InitializeFourBlock()
	{
		GHashFourBlockPrecomputedKey powers = new(Value.ReverseEndianness128());

		try
		{
			return _fourBlock = new(in powers);
		}
		finally
		{
			powers.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashVector128PrecomputedKey> InitializeVector128()
	{
		GHashVector128PrecomputedKey powers = new(Value.ReverseEndianness128());

		try
		{
			return _vector128 = new(in powers);
		}
		finally
		{
			powers.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashVector256PrecomputedKey> InitializeVector256()
	{
		GHashVector256PrecomputedKey powers = new(Value.ReverseEndianness128());

		try
		{
			return _vector256 = new(in powers);
		}
		finally
		{
			powers.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashVector512PrecomputedKey> InitializeVector512()
	{
		GHashVector512PrecomputedKey powers = new(Value.ReverseEndianness128());

		try
		{
			return _vector512 = new(in powers);
		}
		finally
		{
			powers.ZeroMemory();
		}
	}

	internal void Dispose()
	{
		Value.ZeroMemory();
		_fourBlock?.Dispose();
		_vector128?.Dispose();
		_vector256?.Dispose();
		_vector512?.Dispose();
		_fourBlock = null;
		_vector128 = null;
		_vector256 = null;
		_vector512 = null;
	}
}
