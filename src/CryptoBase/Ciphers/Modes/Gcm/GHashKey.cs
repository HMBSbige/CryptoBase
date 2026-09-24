namespace CryptoBase.Ciphers.Modes.Gcm;

internal struct GHashKey
{
	internal Vector128<byte> Value;
	private GHashKeyTable<GHashFourBlockPrecomputedKey>? _fourBlock;
	private GHashKeyTable<GHashVector128PrecomputedKey>? _vector128;
	private GHashKeyTable<GHashVector256PrecomputedKey>? _vector256;
	private GHashKeyTable<GHashVector512PrecomputedKey>? _vector512;
	private GHashKeyTable<GHashArmPrecomputedKey>? _arm;

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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashArmPrecomputedKey> GetArm()
	{
		return _arm ?? InitializeArm();
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashArmPrecomputedKey> InitializeArm()
	{
		GHashArmPrecomputedKey powers = new(AdvSimd.Arm64.ReverseElementBits(Value));

		return CreateTable(ref _arm, ref powers);
	}

	// Keep table construction out of the warm callers' stack frames.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashFourBlockPrecomputedKey> InitializeFourBlock()
	{
		GHashFourBlockPrecomputedKey powers = new(Value.ReverseEndianness128());

		return CreateTable(ref _fourBlock, ref powers);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashVector128PrecomputedKey> InitializeVector128()
	{
		GHashVector128PrecomputedKey powers = new(Value.ReverseEndianness128());

		return CreateTable(ref _vector128, ref powers);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashVector256PrecomputedKey> InitializeVector256()
	{
		GHashVector256PrecomputedKey powers = new(Value.ReverseEndianness128());

		return CreateTable(ref _vector256, ref powers);
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashVector512PrecomputedKey> InitializeVector512()
	{
		GHashVector512PrecomputedKey powers = new(Value.ReverseEndianness128());

		return CreateTable(ref _vector512, ref powers);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static GHashKeyTable<T> CreateTable<T>(ref GHashKeyTable<T>? table, ref T powers) where T : unmanaged
	{
		try
		{
			return table = new GHashKeyTable<T>(in powers);
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
		_arm?.Dispose();
		_fourBlock = null;
		_vector128 = null;
		_vector256 = null;
		_vector512 = null;
		_arm = null;
	}
}
